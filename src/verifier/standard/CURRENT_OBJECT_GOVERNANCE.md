# Current OBJECT-8.1: selected namespace-admission governance decision

Verifier Standard (VSTD) coordinate `OBJECT-8.1` has one experimental,
versioned, bounded proposition. For an externally selected canonical OBJECT
record, namespace identifier, policy revision and evaluation time, the exact
retained decision envelopes contain a configured quorum of distinct Ed25519
(Edwards-curve digital signature algorithm with a 255-bit field) approving
actors. A separate configured status key signs a fresh revocation view; no
selected approval is revoked and no selected veto exists. The verifier
reconstructs the record, policy and evidence commitments and rechecks every
signature. Time is integer Coordinated Universal Time (UTC) Unix seconds;
counts are dimensionless and limits on inputs are bytes.

The policy and evaluation time are independently selected checker inputs.
The policy contains public keys, quorum, scope, revision and effective
interval. Its issuer and the clock source are **not authenticated by this
objective**. PASS means the selected public-key statements meet the selected
computational rule. It does not prove legal authority, legal or ethical
compliance, human agreement, actual namespace admission, execution, registry
completeness, or enforcement. It does not close the whole governance tier,
OBJECT profile, privacy, consent or security obligations. Other OBJECT-8
objectives remain unregistered.

The exact subject is the canonical namespace record digest. Operand targets,
if any, are part of that record but are not resolved by this check. The
decision signatures bind the selected policy digest, record digest,
namespace, action, actor, decision identifier and validity interval. A
separate status signature binds the policy digest, observation interval and
finite revoked-decision list. No private key is retained in a certificate.

PASS requires valid configured signatures, distinct configured actors,
unexpired approvals, an in-force selected policy, a fresh status snapshot,
quorum and no veto or selected revocation. A false exact binding, unauthorized
key, invalid signature, duplicate actor, veto, revoked decision or quorum
shortfall is FAIL. Necessary represented decision constraints are checked
over the complete selected inventory before signature imports. An invalid
signature would refute acceptance; a valid signature cannot repair a false
binding, malformed payload, duplicate identifier, non-current decision or
non-approval. This early refusal authenticates no signer, veto or forgery.
The present status payload also has necessary shape, selected-policy and
bounded time-order constraints. For an otherwise fresh view, its bounded
sorted unique revocation list must exclude every selected decision. A pure
pass checks those constraints before signature imports and authenticates no
revocation. Missing or stale views do not terminate this pass: decision
authentication still precedes status unavailability. Stale views retain
UNKNOWN before revocation-list/refutation checks, preserving the selected
freshness rule. The same status predicates run after authentication.
The present status envelope's exact field set, version, configured key
identifier, object payload and hexadecimal signature grammar are also
necessary represented constraints. They are checked before decision
signature imports and reused by signature verification. Passing grammar
authenticates no signature, identity or revocation.
Missing retained evidence, status, signature backend or a stale status view
is UNKNOWN when no independently decidable refutation exists; it cannot be
promoted to PASS. If a prior positive certificate cannot be replayed because
the signature backend is unavailable and no such refutation exists, replay
status is UNAVAILABLE and the current result is UNKNOWN, not a reproduced
verdict or an accusation of forgery. A substituted
request, policy, mechanism, certificate or claimed verdict is REJECTED at the
public replay boundary. A reproduced certificate always retains the
separate result status.

The public route is selected by semantic version
`verifier-current-object-obligations-1`, objective `OBJECT-8.1`, and
represented kind `OBJECT`. The command-line checker requires externally
selected request and policy files. The certificate retains the exact canonical
evidence bytes and result so a reader with the selected policy can recompute
the bounded proposition. Its record and signatures are public; this format is
unsuitable for confidential governance witness material. Publisher identity,
consent and publication must be checked elsewhere.

The public wrapper uses `verifier-current-object-route-replay-2`. Before returning
UNAVAILABLE, replay rejects carried result, evaluation and observation fields that
contradict independently selected policy or retained record bindings. Those
comparisons do not authenticate signatures or reproduce a prior positive result.


## Exact selected kinds

The same narrow signed namespace-admission predicate is also selected as
`<kind>-8.1` for HUMAN, ACTOR, COLLECTIVE, ROLE, IDENTITY, OWNER, HARDWARE,
RECEIPT, OBJECT, GRAPH, SPACE, TIME, EVENT, ENV, DATA, VERIFIER, BENCH, ARCH,
TRAIN, HYPER, MODEL, HARNESS, AGENT, SIM, BOT and TOKEN. These are the exact
namespace kind labels; they are not alternative meanings for `OBJECT-8.1`.
The original OBJECT coordinate, registration statement, default descriptor,
request and certificate identifiers, and signature domain separation remain.
As before, the mechanism digest binds installed source and specification bytes;
a changed mechanism requires freshly selected policy and evidence. Historical
certificates are not silently upgraded or reinterpreted.

For every selected kind the request binds `object_kind`, its own coordinate
and proposition digest, object identifier and canonical record digest. The
record's digest includes its kind, payload and declared operand identifiers.
Each signed approval binds that digest; changing kind or record therefore
requires new approvals. The retained record must reconstruct with the exact
selected kind. A certificate result must carry the same kind, coordinate and
proposition, including when the signature backend is unavailable. Rehashing a
relabelled certificate cannot establish a different kind's result.

This extension admits no additional action beyond `NAMESPACE_ADMIT`, and it
does not resolve operand targets, check the kind's payload truth or structural
composition, authenticate human identity, establish governance-policy
applicability to the world, consume an admission once, or enforce a registry
write. A HUMAN-8.1 result is about a HUMAN-labelled namespace record, not
permission to govern a person. A MODEL-8.1 result is not model safety or legal
release clearance. Kind-specific substantive laws, ethical obligations,
Distributed Aggregated Governance and smart-contract execution remain separate
propositions. The exact kind selected at the public route must match the
request and native result; one passing predicate does not complete tier 8.

Replay compares the selected request and stable carried result, evaluation and
observation fields by their canonical JavaScript Object Notation (JSON)
representation. An integer, an equal-valued floating-point number and a boolean
are distinct representations: `1`, `1.0` and `true` cannot substitute for one
another. This exact binding also applies when the signature backend is
unavailable; a changed carried value is rejected before an unavailable replay can
be reported. These comparisons do not establish signature authenticity.
