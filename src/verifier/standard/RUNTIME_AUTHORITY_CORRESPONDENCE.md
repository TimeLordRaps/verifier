# Experimental runtime-to-authority correspondence

Verifier Standard (VSTD) runtime-to-authority correspondence is a direct-module
version 0.1 experiment. It requires an independently reproduced bounded deriver
execution whose exact standard-output bytes are a retained event trace, then
replays those events against one exact authority model and finite transition
denominator.

Terminology: JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit
(SHA-256); identifier (ID). Byte limits and event counts are measured in bytes
and dimensionless events respectively. Other IDs and digests are dimensionless.

## 1. Declaration, trace, and execution binding

`verifier-runtime-authority-correspondence-1` binds:

- the inert runtime-authority profile digest;
- exact authority-model, executable-artifact, deployed-artifact, and trace
  digests;
- exact actual-deriver declaration, receipt, checker-source, standard-output
  digest, and standard-output size coordinates;
- a runtime coordinate with runtime kind, platform, runtime version, invocation
  and execution-coordinate digests, deployment coordinate, and event limit;
- an initial authority-model state;
- a one-to-one event-signature-to-authority-transition mapping; and
- a sorted finite coverage denominator equal to the mapped transition IDs.

The supported runtime kind is `verifier-retained-event-trace-replay-1`. The inert
rules and bounds are retained as
`verifier/profiles/runtime-authority-correspondence-profile-1.json`.

`verifier-runtime-authority-trace-1` binds the authority model, executable,
deployed artifact, and runtime-coordinate digest. It retains a gap-free sequence
of unique events. Each event declares event ID, type, actor scope, and action.
These fields select an exact transition mapping; they do not prove actor identity
or authorization.

Before trace interpretation, the mechanism uses the separate actual-deriver
self-status rechecker. The exact executable bytes must reproduce the carried
deriver receipt as `ESTABLISHED`, and its standard output must equal the retained
trace bytes in digest, size, and content. A caller-supplied arbitrary trace cannot
establish runtime correspondence.

## 2. Replay and receipt

The mechanism then strictly decodes the authority model and trace, binds every
shared coordinate, starts at the declared initial state, maps each event to one
authority transition, and reconstructs a contiguous state sequence. It reports
three separate results:

- `coordinate_binding`: exact selected bytes and declared coordinates;
- `observed_transition_correspondence`: whether every observed event maps to a
  possible authority transition from the reconstructed state; and
- `coverage_completeness`: whether observed transition IDs cover the exact
  declared finite denominator.

Correspondence uses `ESTABLISHED`, `REFUTED`, `UNKNOWN`, or `INVALID`.
Coverage uses `COMPLETE`, `INCOMPLETE`, `UNKNOWN`, or `INVALID`. An observed
impossible transition is `REFUTED`; missing or bounded evidence is `UNKNOWN`;
malformed or substituted evidence is `INVALID`. `COMPLETE` coverage does not
upgrade a non-established correspondence result.

`verifier-runtime-authority-correspondence-receipt-1` retains the exact
declaration and selected evidence bytes, all three results, event and transition
coverage, reconstructed states, reason codes, claim boundary, and a body digest.
Recheck validates its body digest and deterministically rebuilds the receipt from
the retained evidence.

Public JSON Schema validation is structural only. It cannot establish canonical
bytes, executable or deployment identity, actual deriver execution, trace
provenance, transition reachability, denominator coverage, or replay equality.

## 3. Bounds and claim boundary

Declarations are at most 262,144 bytes; each model, executable, deployed artifact,
and trace is at most 1,048,576 bytes; selected evidence totals at most 8,388,608
bytes; traces contain at most 1,024 events; models at most 256 states and 256
transitions. The actual-deriver declaration and receipt retain their own bounds.

An established correspondence covers only observed events produced by one exact
bounded execution at one coordinate. Complete coverage is relative only to the
declared finite denominator. Neither establishes unobserved runtime behavior,
actor identity, permission, authorization, sandboxing, secrecy, actual
deployment, deployment continuity, artifact truth, correctness, safety, a
different runtime, or a numbered VSTD profile.

