# Current DATA retained distribution

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Counts and class proportions are dimensionless.
Shannon entropy and its absolute numerical tolerance use bits per observation.

`DATA-3.4`, selected under `verifier-current-object-obligations-1`, checks the
distribution of explicitly selected fields over the complete retained shard
inventory of one exact DATA record. It does not establish the whole statics tier.
The request independently binds that record, the complete finite typed collection,
evidence, policy, proposition, native implementation and checking bounds.

The payload contains `shards` with the digest, record count, canonical byte count,
ordered record digests and ordered Merkle root used by current DATA inventory.
All are recomputed against retained `inputs.shards`. The payload's nonempty
`distribution` maps each selected field to `cardinality`, `classes` and
`entropy_bits`. Every class is `{value, count}` with a positive integer count.
Class identity is exact canonical JSON bytes, so a value and a string containing
its digest are distinct, as are boolean and integer encodings. Class declarations
may be reordered; duplicate values, omitted classes, extra classes and incorrect
counts fail. Every selected field must occur in every retained record.

For N retained records and positive class counts c_i, let p_i = c_i / N.
The native mechanism computes H = -sum_i p_i log2(p_i) with compensated summation.
Here i ranges over exact canonical classes, N and c_i count records, p_i is a
dimensionless fraction, and H is Shannon entropy in bits per observation.
Class balance is reported exactly as numerator c_i and denominator N. The policy
must independently select `entropy_tolerance_bits`, a finite plain number from
zero through 1e-9 bits. This ceiling preserves the legacy numerical ceiling;
it is an absolute floating-point comparison bound, not statistical uncertainty.
A tighter policy can refuse an entropy estimate accepted under a looser policy.

`PASS` means these finite retained-data claims reproduce within the selected
bound. Contradictory data, wrong commitments, malformed classes and false counts
produce `FAIL`. Missing evidence, zero records, zero selected fields or exhausted
resource bounds produce `UNKNOWN`. Selection or certificate substitution is refused.
The canonical certificate must retain its exact evidence for replay and cannot be
redacted into a still-passing certificate. Trust-root labels bind selection; they
do not authenticate a data supplier.

The current request, policy, evidence and certificate each use a distinct
`verifier-current-data-distribution-*-1` version. Legacy `DATA-3.4` keeps its
existing serialized balance labels; there is no automatic certificate conversion.
When two distinct canonical values share one legacy string/digest label, wrong
cardinality is refuted and otherwise the ambiguous legacy representation is
unavailable. The current explicit class-value encoding can represent both values.

Population representativeness, sampling-frame completeness, sensor calibration,
external origin, rights, authenticated authority and full polished-artifact issuance
remain `NOT_ESTABLISHED`. Permuting records or repartitioning exact retained rows
preserves statistics; replicating every row scales counts while preserving entropy
and normalized balance. Neither transformation proves real-world sampling quality.

Reproduce with `vstd current-object check <certificate> --semantic-version
verifier-current-object-obligations-1 --objective DATA-3.4 --represented-kind DATA
--request <request> --policy <policy>`. Source, request, evidence, policy, collection,
or specification changes invalidate previous bindings. Independent finite count
oracles, alias counterexamples, substitutions, budget failures and public replay
checks are in `tests/test_current_data_distribution.py` and
`tests/test_data_distribution_alias.py`.
