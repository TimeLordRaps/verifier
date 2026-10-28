# Current MODEL-3.4: retained training-data citation

Verifier Standard (VSTD) current semantic family
`verifier-current-object-obligations-1` registers one bounded `MODEL-3.4`
proposition. MODEL is the model reproducibility object; DATA is dataset
integrity and lineage. The certificate binds an externally selected exact
MODEL and DATA pair in a finite typed collection. The MODEL's one `data`
operand must name that DATA object. The same DATA object is the externally
selected subject of a separately retained and replayed `DATA-1.2` inventory
certificate. Both the child request and policy are selected outside the
MODEL evidence, and the parent selects the child's exact certificate digest.

The child DATA mechanism recomputes retained shard bytes, counts, ordered
record commitments and digest-tree roots. The parent rechecks that certificate
against the selected child request and policy, and propagates FAIL or UNKNOWN.
The parent cannot turn a missing, false or unverifiable child result into PASS.
Canonical JavaScript Object Notation (JSON), canonical base64 and Secure Hash
Algorithm 256-bit (SHA-256) commitments bind the selected bytes. Counts are
dimensionless; byte limits count encoded bytes.

`PASS` establishes an exact MODEL-to-DATA artifact citation and local replay
of the selected retained inventory. It does not establish that any training
run consumed those records, that a retained dataset is complete, or that its
origin, rights, consent, sampling quality or claimed labels are true. It does
not establish MODEL provenance, whole statics-tier conformance, or authority
to publish the dataset. The canonical parent certificate contains the child
certificate and its retained DATA records. Use it on a public surface only
when that disclosure has been independently authorized. Redacting retained
evidence cannot preserve a canonical replayable certificate.

The native application programming interface (API) is `model_data_policy`, `model_data_request`,
`build_model_data_certificate` and `recheck_model_data_certificate` in
`verifier.domains.contracts.model_data_citation`. The public route uses `vstd current-object check` with the exact semantic version,
`MODEL-3.4`, represented kind `MODEL`, and selected request and policy.
Public replay requires the installed checker and its packaged specifications.
Its current result leaves actual training use,
origin rights, complete inventory, disclosure authority and the whole tier
`NOT_ESTABLISHED`.
