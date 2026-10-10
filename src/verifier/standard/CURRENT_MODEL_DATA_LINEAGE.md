# Current MODEL-3.7: mediated retained training-data lineage

Verifier Standard (VSTD) current semantic family
`verifier-current-object-obligations-1` registers the new internal tier-3
objective `MODEL-3.7`. MODEL denotes a model reproducibility object, TRAIN a
training-run specification, and DATA dataset integrity and lineage. Tier 3
asks which selected external constraints and invariants hold. This objective
tests an exact static relation between the MODEL, its TRAIN operand and two
distinct retained DATA views. The positive index 7 is a new current grounding
objective, not a migration or alias of any legacy `MODEL-3.*` obligation.

An independently selected exact MODEL has one `data` operand naming a shard
inventory DATA record and one `train` operand naming a TRAIN record. That TRAIN
has one `data` operand naming a different batches-only DATA record. A retained
`MODEL-3.4` child replays the MODEL-to-inventory DATA citation and its
`DATA-1.2` child. A retained `TRAIN-1.5` bridge child replays `TRAIN-4.1` over
the batch view and the *same exact* `DATA-1.2` child selection and certificate
over the inventory view. The two parent children must bind the same exact
finite namespace collection, and their retained collection bytes must compare
equal. The parent also checks every selected MODEL, TRAIN and DATA operand
and object digest. This does not change `MODEL-3.5` version 1's one-DATA
operand proposition.

`PASS` establishes this exact retained mediated data-lineage relation under
the selected child mechanisms and bounds. A child `FAIL` or `UNKNOWN`
propagates; missing evidence and exhausted selected limits remain `UNKNOWN`.
Changed child bytes, selections, object operands, collection bytes or installed
mechanisms fail or are rejected. Canonical JavaScript Object Notation (JSON),
base64 and Secure Hash Algorithm 256-bit (SHA-256) bind retained bytes. Counts
are dimensionless. One mebibyte (MiB) is 1,048,576 bytes. Defaults admit
256 objects, 4,096 items per container, 100,000 native and composition
operations, 12 MiB of parent evidence, 3 MiB for the MODEL-3.4 child, 5 MiB
for the TRAIN-1.5 child, and a 16 MiB parent certificate.

This is retained-artifact replay. It does **not** establish historical
execution, actual consumption, valid or complete discarded training history,
MODEL weight derivation, external origin, data rights, consent, authority to
disclose either child, whole statics-tier conformance or polished issuance.
Both child certificates and their nested evidence remain in the canonical
parent; a redacted parent cannot remain canonical or independently replayable.
Private-witness public proof needs a separate protocol and authorization.

The native application programming interface (API) is
`model_data_lineage_policy`, `model_data_lineage_request`,
`build_model_data_lineage_certificate` and
`recheck_model_data_lineage_certificate` in
`verifier.domains.contracts.model_data_lineage`. Public command replay
requires a separately qualified route selecting this semantic version,
`MODEL-3.7`, represented kind MODEL, exact request and policy. Native replay
alone is not authority, public disclosure, polished issuance or release.
