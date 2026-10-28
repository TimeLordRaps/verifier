# Architecture

> **Acronyms:** conjunctive normal form (CNF); Boolean satisfiability problem (SAT);
> Verifier Standard (VSTD).

## Roles

1. **External verifier object:** defines the accepted witness shape and executes the authoritative bounded predicate.
2. **LM:** proposes either a complete candidate (Arm B) or a finite witness route (Arm C). It is not a truth oracle.
3. **Generic harness:** validates a closed route language and accounts for all work. It contains no held-out-specific search policy.
4. **Generic SAT backend:** compiles finite domains to deterministic one-hot CNF and calls the same pinned CaDiCaL configuration for every domain.
5. **Decoder:** maps one selected value per slot into the verifier's predeclared witness shape.
6. **Native verifier:** accepts, rejects, or errors on that exact candidate and instance.
7. **VSTD binding:** binds content digests, route/formula/candidate lineage, outcomes, resource bounds, and permitted/prohibited inferences.

## Generic route language

`vgsat-route-0.1` is an experiment-local label, not a VSTD wire identifier. Its slots have bounded integer domains. Its closed constraint set is:

- `fixed`
- `allowed_values`
- `all_different`
- `forbidden_pair`
- `allowed_pairs`
- `product_equals`

Unknown fields, unknown constraint kinds, duplicate values, missing decoder slots, and declared limits violations fail closed. Each slot is encoded exactly once. Deterministic slot/domain/constraint order fixes variable and clause order.

The outer Arm B and Arm C response objects are closed too. Extra top-level fields
are rejected rather than ignored. LM request errors, malformed proposal contracts,
route compilation errors, and route execution failures are bound as explicit
failure observations and preserve `UNKNOWN`.

The language is generic but not magically domain-complete. In Arm C, the LM must express a route using this language. The held-out adapter supplies only the existing verifier, instance, and witness decoder. A route that fixes every slot is labeled generate-and-check-equivalent and cannot support a SAT-assistance claim.

## Comparison arms

- **A — canonical SAT:** complete domain-specific bounded encoding, unchanged generic compiler/SAT backend, decoded candidate, native verifier.
- **B — LM generate-and-check:** complete LM candidate, native verifier, no SAT completion.
- **C — verifier-first route:** LM route, generic compilation and SAT completion, decoder, native verifier, VSTD record.

Arm A is deliberately separated in `baselines.py`. It is not shown to the Arm C LM. Arm C therefore does not receive the human-built complete SAT encoding through an adapter.

## VSTD use

The integration imports the existing canonical digest and provenance hypergraph implementation. It does not issue a normative `VstdReceipt`, create a schema `$id`, or coin a frozen wire identifier. Each record contains:

- stable payload and canonical binding digest;
- canonical content payloads for every graph node;
- exact per-trial solver configuration and digest;
- graph edges from instance through route, formula, solver observation, candidate, and native observation;
- an explicit failure node when LM generation, proposal validation, compilation, or route execution fails;
- structural validation and reexecution support.

Graph `VALID` means the stored artifact bytes match the node digest. It does not mean the artifact's semantic claim is true. The separate `bounded_claim_status` is `PASS` only for an accepted candidate; all unsuccessful routes remain `UNKNOWN` about the domain.

Every final record is checked twice. The producer-aware validator recompiles the
route and uses the provenance hypergraph implementation. A separate consumer validator does
not import the producer canonicalizer, route compiler, VSTD binding, or SAT
backend: it independently canonicalizes and rehashes the record, checks graph
payloads and edges, submits the bound CNF directly to the pinned solver, decodes
the resulting model from the recorded variable map, and reexecutes the native
verifier. Shared use of the authoritative native verifier and selected SAT binary
remains an explicit trust boundary.

## Timing

Timers use `perf_counter_ns`. Total work includes verifier/contract and prompt
preparation, LM generation, proposal handling and compilation, SAT, native verification,
unattributed orchestration, a same-input VSTD creation probe, and a producer-aware
plus separate-consumer reverification probe. The probes run on a complete first
record and are bound into a second final record because an artifact cannot include
the time needed to finish its own digest. `total_system_probe` is the bound sum of
the direct pre-record wall time and those two probes; final-artifact QA occurs
afterward and is not silently added to the performance comparison.

## Domain-specific surface

The primary verifier wrappers and complete Arm A encodings are domain-specific. The route compiler, solver, LM interface, harness policy, record binding, metrics, and result validator are generic. [engineering-surface.json](engineering-surface.json) counts nonblank, non-comment physical lines by these predeclared file groups; vendored upstream sources and tests are excluded.
