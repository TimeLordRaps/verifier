# Current MODEL-3.5: retained training-run citation

Verifier Standard (VSTD) current semantic family
`verifier-current-object-obligations-1` registers one bounded `MODEL-3.5`
proposition. MODEL is the model reproducibility object; TRAIN is the training
run specification; DATA is dataset integrity and lineage. An externally
selected exact MODEL has one `train` operand naming an exact typed TRAIN record.
The TRAIN and MODEL each have one `data` operand naming the same exact DATA
record in one finite typed composition. An exact, separately selected
`MODEL-3.4` certificate over that same MODEL, DATA and collection is retained
and locally replayed. The parent selects the child request, policy and exact
certificate digest outside the retained evidence.

`PASS` establishes this declared MODEL-to-TRAIN citation, agreement on the
declared DATA object and reproduction of the bounded MODEL-3.4 retained DATA
inventory citation. A child `FAIL` or `UNKNOWN` remains `FAIL` or `UNKNOWN`.
Malformed or substituted selected evidence is refused. JavaScript Object
Notation (JSON), canonical base64 and Secure Hash Algorithm 256-bit (SHA-256)
commitments bind exact bytes. Counts are dimensionless; byte limits count
encoded bytes. Defaults admit 256 objects, 4096 items per container, 100000
native and composition operations, 8 MiB of evidence, a 4 MiB child
certificate and a 10 MiB parent certificate (MiB = 1048576 bytes).

The citation does **not** establish that the TRAIN record represents an actual
execution, that its checkpoints or numerical updates are valid, that it
consumed the retained DATA records, or that it produced the MODEL weights.
Origin, rights, consent, complete history, authority to disclose the records,
whole object-profile or statics-tier conformance and polished issuance also
remain `NOT_ESTABLISHED`. TRAIN-1.3 currently requires a DATA payload containing
exactly `batches`, while DATA-1.2 replays `shards` commitments. A future
versioned bridge must reconcile those distinct exact payload contracts before
one identical DATA record can support both replay mechanisms; this citation
does not silently claim that bridge.

The canonical parent certificate retains the MODEL-3.4 certificate, which
itself retains DATA records. Public disclosure requires separate authority;
redacting the evidence does not preserve a canonical replayable certificate.
The native application programming interface (API) is `model_train_policy`,
`model_train_request`, `build_model_train_certificate` and
`recheck_model_train_certificate` in
`verifier.domains.contracts.model_train_citation`. The public route uses `vstd current-object check` with the exact semantic version,
`MODEL-3.5`, represented kind `MODEL`, and selected request and policy. Public
replay requires the installed checker and its packaged specifications.
