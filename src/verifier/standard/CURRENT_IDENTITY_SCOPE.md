# Current declared identity role and scope admission

Verifier Standard (VSTD) semantic version `verifier-current-object-obligations-1`
registers `IDENTITY-3.1` for finite declared role and scope admission. This statics
objective checks the constraints in [the identity contract](IDENTITY_OCCUPANCY.md),
including the current HUMAN, AGENT and BOT representations, without changing any
legacy numbered-profile meaning or completing the identity statics tier.

The independently selected IDENTITY must occur exactly once with its exact record
digest in the selected finite collection. All retained namespace records must
reconstruct exactly and satisfy finite typed composition. The retained declaration
and IDENTITY payload must agree on one ACTOR, represented object and kind, responsible
HUMAN, one ROLE, selected COLLECTIVE and scope. The ROLE must belong to that COLLECTIVE;
its declared admitted scopes must include the identity scope. A BOT scope must name
one of its bound SIM (simulation) objects. The checker executes these constraints;
neither a carried result nor a declaration digest supplies the verdict.

The public selection fixes semantic version, objective and represented kind IDENTITY.
The request fixes subject identifier and record digest, collective identifier,
declaration digest, complete collection digest, retained evidence reference, policy,
proposition and finite limits. The separately selected policy fixes installed code,
direct dependencies, this specification, the identity contract and namespace rules.
Trust-root labels do not authenticate the selector or a declaration's author.

Evidence uses canonical JavaScript Object Notation (JSON) with exactly `schema_version`,
`objects` and `declaration`. Its identifier is `verifier-current-identity-scope-evidence-1`.
The objects are exact namespace records. The declaration retains the identity contract's
existing `verifier-namespace-identity-evidence-1` meaning, including its unresolved
evidence locator; absent declaration bytes remain UNKNOWN. Secure Hash Algorithm
256-bit (SHA-256) commitments select exact bytes under collision-resistance assumptions.
They do not authenticate people, authority or live occupancy.

`verifier-current-identity-scope-certificate-1` retains all evidence needed for local
replay. The rechecker rebuilds the canonical certificate and compares every byte.
Substituted requests, policies, dependency bytes, evidence or rehashed carried results
refuse admission. Canonical certificate evidence cannot be selectively redacted.

PASS establishes only that exact finite declared relation. Contradictory records,
declarations, membership or scope produce FAIL. Missing evidence, unspecified scope
admission, an unsupported selected declaration version, or exhausted bounds produce
UNKNOWN. Malformed external selection or certificate transport refuses admission.
Human authenticity, live occupancy, delegated authority, evidence-locator resolution,
privacy, consent, governance and object-profile conformance remain NOT_ESTABLISHED.

Limits are positive plain integers. The certificate permits at most 256 objects,
100,000 composition operations as defined by the namespace checker, and separately
100,000 relation traversal steps. A relation step pops one operand reference, including
repeated visits, across all actor, role, collective, representation, root and simulation
expansions; an expansion that cannot fit the remaining steps stops with UNKNOWN.
Composition and relation budgets count distinct phases and are dimensionless. Each of
evidence, payload and reference bytes is capped at 4 mebibytes; certificate bytes at
8 mebibytes. One mebibyte is 1,048,576 bytes. Byte bounds, record counts and finite
admission rules additionally bound parsing, capture, indexing and scope comparison;
operation counters are not instruction counts or wall-clock guarantees.

Falsifiers include a role outside the selected collective, scope outside declared
admission, a BOT naming another simulation, substitution of any independently selected
commitment, malformed retained operands, and a rehashed result claiming authority.
`vstd polish` may replay this objective only for the exact subject and collection.
Complete objective coverage, authenticated authority, public checkability and polished
issuance require separate mechanisms and evidence.

Retained-reader capacity availability is a distinct boundary. Decoder recursion,
overflow and explicitly unavailable checking capacity raise `IdentityScopeUnavailable`,
an `OSError` subtype, and current public routes preserve UNKNOWN. This capacity
category does not establish replay or refute the selected predicate. Demonstrated
selection substitutions, malformed semantic bytes and exact-reconstruction
contradictions remain `IdentityScopeError` refusals; ordinary `ValueError` is never
downgraded to unavailability. Evaluator capacity exhaustion remains UNKNOWN.
An already observed FAIL is retained; no uninspected later predicate is certified.
Source/mechanism changes require freshly selected policies and certificates;
previous exact bytes and their genuine verdicts are not rewritten.

A decoder recursion/overflow occurring inside native evidence replay is retained
as UNKNOWN with the explicit observation `checking_resource_unavailable: true`.
If that unavailable replay cannot reproduce earlier complete certificate bytes,
recheck raises IdentityScopeUnavailable and never returns the carried outcome.
Independent envelope, exact proposition, result-shape and claim-boundary
contradictions are refused before replay. Ordinary semantic mismatches remain
IdentityScopeError. A naturally missing or bounded UNKNOWN result that reproduces
its exact bytes remains a genuine reproduced UNKNOWN; no carried PASS is accepted.

After exact evidence import and before native invocation, the retained evaluation
byte count equals the actual selected payload length, or zero when absent. This
independently decidable contradiction refuses even if later decoding capacity is
unavailable; the carried count is never used as a resource allowance.
