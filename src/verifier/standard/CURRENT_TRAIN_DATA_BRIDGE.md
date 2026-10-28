# Current TRAIN-1.5: retained batch-to-shard bridge

Verifier Standard (VSTD) current semantic family
`verifier-current-object-obligations-1` registers a bounded `TRAIN-1.5`
proposition. TRAIN denotes a training run specification and DATA denotes dataset
integrity and lineage. JavaScript Object Notation (JSON), canonical base64 and
Secure Hash Algorithm 256-bit (SHA-256) bind retained bytes. Counts are
dimensionless. One mebibyte (MiB) is 1,048,576 bytes.

An externally selected `TRAIN-4.1` child replays a finite retained step trace
against a batches-only DATA view. A separately selected `DATA-1.2` child replays
shard records against an exact DATA inventory. Both children retain their
existing version 1 wire contracts. The parent selects their exact requests,
policies and certificate digests, the TRAIN batch-view record, and a nonempty
sorted set of shard names. It rechecks both child certificates and recomputes a
mapping from every selected shard record's canonical batch bytes to its SHA-256
digest. That map must exactly equal the TRAIN view's batch map. The TRAIN-4.1
child requires each retained step's batch digest to resolve in that map and
rejects unreferenced batch entries. Duplicate selected batches are refuted.

`PASS` establishes this exact selected retained representation relation.
Individually valid child certificates can still disagree and then the bridge
returns `FAIL`. Child `FAIL` or `UNKNOWN` propagates without promotion;
missing retained evidence and exhausted selected limits remain `UNKNOWN`.
Substituted or malformed selected bytes fail or are rejected. Defaults permit
100,000 bridge operations, 4,096 items per container, 8 MiB of evidence,
2 MiB per child certificate, and a 10 MiB parent certificate. Public
disclosure requires separate authority because the parent retains both child
certificates and their evidence. Redacting a canonical parent does not preserve
its replayability.

This does not prove that historical execution occurred or consumed the selected
records. It does not establish unretained data, external origin, rights,
consent, model-weight derivation, full `TRAIN-1.4` prerequisites, whole facets
tier, whole object-profile conformance or polished issuance. The selected
shards are the stated scope; other inventory shards are not claimed as training
batches. The parent does not change `TRAIN-4.1` or `DATA-1.2` semantics.

The native application programming interface (API) is
`train_data_bridge_policy`, `train_data_bridge_request`,
`build_train_data_bridge_certificate` and
`recheck_train_data_bridge_certificate` in
`verifier.domains.contracts.train_data_bridge`. Public replay requires a
separately qualified route selecting the semantic version, `TRAIN-1.5`, kind
TRAIN, exact request and policy. A native module alone is not public
checkability.
