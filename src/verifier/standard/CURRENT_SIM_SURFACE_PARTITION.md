# Current simulation (SIM) finite surface accounting

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash Algorithm
256-bit (SHA-256). Times and state values retain the selected model's units.
Byte limits count bytes; operation and item counts are dimensionless.

## Selected proposition and compatibility

`verifier-current-object-obligations-1`, `SIM-4.4`, means exact accounting for an
externally selected **finite declared state partition**, including transition
attribution. This distinct current route does not reinterpret legacy SIM-4.4
(no unattributed transition) or SIM-4.5 (whole-surface accounting) certificates.
It is a bounded part of current simulation closure, not complete tier conformance.

An exact selected passing [SIM-4.3 child](CURRENT_SIM_SHARD_SIGNATURES.md) must
bind the same simulation, object and collection. Replay that child under its
separately selected request and policy, including its SIM-4.2, SIM-4.1 and
[SIM-2.1](CURRENT_SIM_DYNAMICS.md) prerequisites. A carried verdict is not evidence.

The external map binds its exact canonical digest in the request. Every root
state variable must occur exactly once and map to exactly one `(shard_id,
shard_variable)` pair. Every declared shard field must occur exactly once.
Missing, extra or multiply attributed fields fail. The root and shard field
inventories must remain exact at every retained time. At each aligned time,
each mapped value must have identical canonical bytes; integer and floating
point representations are distinct. No numeric tolerance or projection is used.

Each map row binds the canonical SHA-256 digest of that root variable's exact
transition expression. The child trajectory replay establishes application of
that expression at every retained step. Attribution covers unchanged transitions
as well as observed changes; a state difference cannot create its own attribution.

## Exact records

The request has `schema_version`, `semantic_version`, `coordinate`,
`proposition_digest`, `object_kind`, `subject_id`, `object_digest`,
`collection_digest`, `signatures_request_digest`, `signatures_policy_digest`,
`signatures_certificate_digest`, `surface_digest`, `evidence_ref`, `policy_digest`
and `limits`. Its schema is `verifier-current-sim-surface-partition-request-1`.

The policy uses `verifier-current-sim-surface-partition-policy-1`, the exact
installed mechanism digest, nonempty sorted unique external trust-root labels
and a bounded `max_certificate_bytes`. Labels alone confer no authority.

Evidence uses `verifier-current-sim-surface-partition-evidence-1` and exactly
`schema_version`, `signatures_request`, `signatures_policy`,
`signatures_certificate` and `surface`. The selected child is canonical base64.
Absent child or surface is represented by `null`; all selections remain bound.

The surface has exactly `schema_version` and `partitions`. Its schema is
`verifier-current-sim-surface-map-1`. `partitions` is a nonempty finite array of
exact records with `root_variable`, `shard_id`, `shard_variable` and
`transition_digest`. Names are nonempty strings of at most128 characters.

The canonical envelope uses `verifier-current-sim-surface-partition-certificate-1`:
request, policy/mechanism/proposition commitments, one selected retained evidence
reference and payload, reconstructed result and digest. Recheck rebuilds the entire
envelope from retained bytes. Forged status, substituted policy/subject/child,
noncanonical encoding or a rebuilt-envelope mismatch is rejected.

## Verdicts and bounds

PASS requires child replay PASS, exact commitments, bijective field coverage,
canonical values at every retained time and exact transition attribution. A known
contradiction or failed child yields FAIL. Missing selected evidence, an unavailable
child mechanism/backend or an exhausted checking budget yields UNKNOWN.

If exact child reproduction fails, reconstruct its selected evidence under its
current policy. An UNKNOWN reconstruction may yield only parent UNKNOWN, after
checking canonical envelope integrity, exact non-result bindings, static result
and evaluation fields, and independently countable carried positive observations.
Absent required keys/signatures, mismatched counts, promoted authority or exceeded
selected bounds still refute a carried PASS. This path never accepts that carried
verdict or establishes signature validity. Other reproduction mismatches fail.
There are at most two child replay attempts; each retains its own selected bounds.

Ceilings are1000000 operations,4096 items per collection,8388608 evidence bytes and
16777216 certificate bytes. Selected limits may be smaller. Fixed-depth child
decoding charges each decoded certificate and payload plus structural traversal
before interpretation. Each child retains its own independently selected limits;
the parent's budget does not replace them or guarantee an arbitrary runtime bound.
This new checker has a separate work ceiling because it unpacks four nested child
envelopes and payloads. It does not enlarge any existing child checker budget.

## Exclusions and invalidators

Accounting is conditional on the exact external finite declaration. It does not
prove coverage of hidden process memory, physical reality, unretained states,
nonlinear projections, entropy/action/observation channels, independent origin,
historical execution or cryptographic backend correctness. Signatures retain the
child's selected required-shard policy; this check does not extend it to other
shards. Whole runtime surface, whole tier conformance, authority, privacy, consent,
governance, security and publication eligibility remain unestablished.

Changed selected object/collection, map, expressions, rows, child selections,
policy, backend availability/version, installed checker or specification bytes
invalidate prior reliance. Replay uses
`vstd current-object check CERT --semantic-version verifier-current-object-obligations-1 --objective SIM-4.4 --represented-kind SIM --request REQUEST --policy POLICY`.
The implementation is `verifier.domains.contracts.sim_surface_partition`; independent
tests include later-only mismatches, canonical representation substitution, extra
fields, duplicate attribution, failed/unavailable children and rehashed forgery.
