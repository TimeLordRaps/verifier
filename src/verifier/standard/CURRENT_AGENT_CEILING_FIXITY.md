# Current AGENT-3.1: observation ceiling fixed by the bound harness

Status: experimental, versioned current-object objective. Verifier Standard
(VSTD) specifies the claim; this Python mechanism is one reference checker.
JavaScript Object Notation (JSON) gives canonical retained bytes, and Secure
Hash Algorithm 256-bit (SHA-256) names commitments. Observation ceilings,
counts and checking budgets are dimensionless integers.

## Row

The pair `verifier-current-object-obligations-1` / `AGENT-3.1` selects a
bounded strict subset of this row of `DOMAIN_OBLIGATIONS.md`, quoted verbatim:

| AGENT-3.1 | Ceiling fixity | The observation ceiling is fixed by the harness, not by the agent. | none | statics:ceiling |

## Proposition

The externally selected exact AGENT record occurs once in the selected finite
typed collection; its harness operand binds exactly one HARNESS record of that
collection; that HARNESS record states an observation ceiling; and the AGENT
record's declared observation ceiling equals the bound HARNESS record's
ceiling under statics:ceiling, so the only ceiling reported is the harness's.

## Retained bytes

Evidence is the canonical JSON object `{"schema_version":
"verifier-current-agent-ceiling-fixity-evidence-1", "objects": [...]}`. Each
row is one namespace record `{object_id, kind, payload, operands}` and must
reconstruct exactly. The request commits the subject digest, the composition
digest of every row and the SHA-256 of the evidence bytes.

- The AGENT payload is exactly `{"scope": "retained-agent-ceiling-fixity",
  "declared_ceiling": <integer or null>}`.
- The bound HARNESS payload may carry other keys. Its `observation_ceiling`
  value is the `statics.py` harness object `{"ceiling": <integer>,
  "observed": [...]}`, reused unchanged.

## Decision

1. Non-canonical or wrong-version evidence, a subject that is absent,
   repeated, of another kind or of another digest, and a typed composition
   that fails `assess_composition` are `FAIL`. A wrong AGENT scope is `FAIL`.
2. An exhausted object, item, operation or composition bound is `UNKNOWN`.
   So is missing evidence. So is a harness operand that binds a typed GRAPH
   or more than one record rather than one HARNESS record. So is a bound
   HARNESS payload without `observation_ceiling`, and a `null` declaration,
   which `statics.py` reads as an absent `declared_ceiling`.
3. Otherwise `statics.evaluate("AGENT", "ceiling", {"harness":
   <bound observation_ceiling>, "declared_ceiling": <declared>}, {}, budget,
   subject=<subject_id>)` decides. It reads only the bound harness and the
   agent's declaration. A declaration that differs from the harness ceiling,
   above or below it, is `FAIL`: the row requires equality, not a bound.
   Malformed ceiling values are `FAIL`.
4. `PASS` reports `harness_id` and `harness_ceiling`, both read from the bound
   HARNESS record. Another HARNESS record in the collection, even one whose
   ceiling equals the declaration, cannot be selected.

## Relation to other AGENT coordinates

`agent_checks.py` registers AGENT-1.8 (harness), AGENT-2.1 (trajectory),
AGENT-2.3 (actions), AGENT-4.1 (outcomes) and AGENT-4.3 (claims). Those
replay HARNESS child certificates and treat the ceiling as a set of
instrumented channels. This objective uses no child certificate and decides
one integer equality between two exact namespace records. AGENT-3.2
(unknowability) and AGENT-3.3 (declaration impotence) are other rows of this
tier and remain `NOT_ESTABLISHED` here. The inventory rationale for this
slot names memory bounds, guardrails and non-escalation. None of these is
established by this objective.

## Exclusions

`PASS` does not show that any harness enforced the ceiling, or that the agent
observed only what it allows. It establishes no real-world identity of either
record, and no authority, safety, security, privacy or consent. It does not
close the AGENT statics tier, and it does not establish object-profile
conformance. Each of these is `NOT_ESTABLISHED`.

Changed AGENT or HARNESS records, collection, evidence bytes, limits, policy,
`statics.py`, this mechanism or this specification invalidates the pinned
mechanism.
