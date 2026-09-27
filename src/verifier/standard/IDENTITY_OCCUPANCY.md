# Versioned declared identity and role binding

Verifier Standard (VSTD) distinguishes a finite declaration from actual role
occupancy. `verifier.domains.contracts.identity_occupancy` checks one selected
IDENTITY in an exact, caller-selected collection of namespace objects. This
new contract does not reinterpret historical `verifier.domains.identity`
receipts or silently promote legacy `IDENTITY-*.m` results to the current
eight-tier object hierarchy. All counts and identifiers here are dimensionless.

The checker requires exactly one ACTOR and one ROLE reachable from the selected
IDENTITY. The ACTOR represents exactly one HUMAN, AGENT or BOT, with an explicit
root HUMAN. The ROLE must be in the selected COLLECTIVE's role graph. The
IDENTITY, evidence record, and checker-selected evidence digest must bind the
same actor, role, collective, represented kind and object, root human, and
scope. The collection digest commits to every supplied object and reference.
Graph expansion follows only typed, finite operands already accepted by the
composition checker. A BOT's declared scope must be `simulation:<sim_id>`,
where `sim_id` is the identifier of one SIM (simulation) bound to the BOT.
Several SIM operands may be present, but each IDENTITY declaration selects
one exact simulation scope.

The evidence record has `schema_version` equal to
`verifier-namespace-identity-evidence-1` and exactly these bounded, nonblank string fields:
`identity_id`, `actor_id`, `role_id`, `collective_id`,
`representation_id`, `actor_kind`, `root_human_id`, `scope`, and
`evidence_ref`. `evidence_ref` is a canonical Secure Hash Algorithm 256-bit
(SHA-256) `sha256:` digest locator;
this check does not resolve its bytes. The IDENTITY payload binds the evidence
digest as `binding_evidence_digest` and the same `scope`. The ROLE payload's
`admitted_scopes` is a bounded nonempty list of nonblank strings; a blank entry
invalidates even a list that also contains the selected valid scope. It is a **declaration**, not
independent authority evidence.

The `verifier-namespace-identity-assessment-1` result is `PASS` only for that
finite declared relation. An absent selection, absent evidence, missing ROLE
scope declaration, unsupported evidence version, or exhausted composition
bound yields `UNKNOWN`. Contradictory selected bytes, malformed evidence,
broken object relations, or a scope outside the ROLE declaration yields
`FAIL`. `recheck_identity_occupancy` recomputes all assessment fields from the
selected inputs; a rehashed carried `PASS` is insufficient.

Even at `PASS`, human authenticity, actual occupancy or liveness, delegated
role authority, retained evidence resolution, privacy, consent, governance,
and each object's numbered-profile conformance remain `NOT_ESTABLISHED`.
The digest commitments select and replay bytes; they do not authenticate their
source. A current `[OBJECT]-1..8.m` grounding certificate requires its own
registered proposition, mechanism, independent evidence, and replay.
