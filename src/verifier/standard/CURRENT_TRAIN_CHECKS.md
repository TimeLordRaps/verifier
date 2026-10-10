# Current retained training checks

Training run specification (TRAIN); dataset integrity and lineage (DATA);
benchmark specification graph (BENCH); model or algorithm architecture (ARCH);
Verifier Standard (VSTD); JavaScript Object Notation (JSON); stochastic gradient
descent (SGD); adaptive moment estimation (Adam); Adam with decoupled weight decay
(AdamW); rectified linear unit (ReLU). EVENT, TIME, SPACE and OBJECT name namespace
kinds for declared events, indices, retained scope and meaning. Numerical values
carry their selected contract units; indices and operation counts are dimensionless.

These experimental propositions use `verifier-current-object-obligations-1`.
The independently selected request binds the subject, collection, evidence,
native check, proposition, installed mechanism, policy and finite limits.
Every record reconstructs exactly and passes typed finite composition.

| Current coordinate | Native check | Bounded proposition |
|---|---|---|
| TRAIN-1.2 | configuration | Admit and bind the optimizer, constant schedule, accumulation and ordered Python binary64 contract. |
| TRAIN-1.3 | checkpoints | Rehash each weight and optimizer-state record and check dense tensor shapes against the selected architecture. |
| TRAIN-2.1 | training | Recompute retained losses, analytic gradients, optimizer updates and moments across the selected trace. |
| TRAIN-2.3 | updates | Recompute updates and moments from retained gradients; this does not establish the gradients' relationship to the loss. |
| TRAIN-4.1 | lineage | Check contiguous indices and exact parent, result, configuration and batch bindings in retained event order. |

Current TRAIN-1.1 continues to mean typed structural facets. Legacy TRAIN-1.1
means optimizer contract; it is not overwritten. Current TRAIN-1.2 explicitly
includes optimizer admission with numerical semantics. This selected proposition
does not fulfill every legacy prerequisite or automatically register neighboring
objectives. Existing legacy identifiers retain their meanings.

The TRAIN payload is the native artifact: configuration, architecture,
checkpoint_digests, steps_digest, start_step and tolerance. Evidence contains
exactly schema_version, objects and inputs. Inputs admit checkpoints, steps and
batches; unsupported fields are refuted. Absent required support remains UNKNOWN.
Configuration checks do not require checkpoint bytes; checkpoint inventory does
not assert numerical moment validity, gradient correctness or history completeness.

The supported composition has one ARCH payload exactly equal to architecture;
one DATA payload containing exactly batches; and one BENCH payload exactly
`{"loss":"mean-squared-error","reduction":"mean-samples-and-outputs",
"arithmetic":"python-binary64","relu_derivative_at_zero":0}`. That BENCH selects
the same DATA and one VERIFIER payload containing exactly this contract's
mechanism_id and installed mechanism_digest. This binds the loss predicate,
not a performance benchmark, empirical validity or general checker correctness.

Ordered EVENT operands each contain exactly training_step. Their TIME payload
is exactly index with that step's index; SPACE is exactly scope with value
retained-training-trace; OBJECT meaning is exactly operation=optimizer-update
and configuration_digest for the selected configuration. Each role selects one
record. The ordered event-step digest must equal steps_digest; supplied steps
and batches must exactly equal their event and DATA representations. Unsupported
operand multiplicities remain UNKNOWN. These are retained declarations, not
authenticated physical observations or proof that execution occurred.

Numerical replay follows [the native contract](DOMAIN_GROUNDING.md#numerical-semantics):
ordered Python binary64, dense linear/ReLU networks, mean squared error over
samples and outputs, equal-sized microbatch accumulation, global gradient
clipping, and SGD/Adam/AdamW updates. The request-bound artifact selects tolerance.
No exact-real, accelerator, mixed-precision, distributed or general convergence
claim follows. A nonzero selected start establishes no earlier history.

Evidence structure is charged before native work. Defaults admit 256 objects,
4096 items per container, 100000 native and composition operations, 4 MiB evidence,
payload and reference bounds, and 8 MiB certificates (MiB = 1048576 bytes).
Namespace records also retain their own byte ceiling. Exhausted bounds remain
UNKNOWN. Recheck rebuilds the entire canonical certificate and rejects promotions
or substitutions even when its outer digest has been recomputed.

The implementation commitment includes the training and numerical checkers,
common primitives, namespace, certificate/evidence/receipt machinery,
`NAMESPACE_OBJECTS.md`, `DOMAIN_GROUNDING.md`, this specification and the
local interpreter identity. A dependency or runtime change requires policy
readmission. The runtime commitment does not authenticate the interpreter,
prove that retained work executed there or establish equivalence across
runtimes. The optional runtime-qualified wrapper remains separately selected.
Public selection uses `vstd current-object check` with explicit semantic
version, objective, represented kind, request and policy. Full profile
conformance, public checkability, authority and polished issuance remain
unestablished.
