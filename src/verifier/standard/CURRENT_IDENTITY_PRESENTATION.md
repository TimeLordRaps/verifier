# Current configured identity presentation prerequisites

JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
American Standard Code for Information Interchange (ASCII); Unicode Transformation
Format, 8-bit (UTF-8); null (NUL); central processing unit (CPU); identifier (ID);
hash-based message authentication code (HMAC).

Verifier Standard (VSTD) semantic version `verifier-current-object-obligations-1`
registers objective `IDENTITY-4.1`, scope
`finite_configured_identity_presentation_prerequisites`. This bounded prerequisite
objective does not reinterpret legacy identity coordinates or legacy whole closure.

The native checker actually reproduces both independently selected IDENTITY-3.1
and IDENTITY-2.1 certificates. The complete request, policy and certificate byte
tuples are external selections. Subject, full object record, full collection,
binding, presentation inventory, clock and evaluation time agree. The selected
native2 policy must embed the identical selected native3 policy/request/byte pin.
Neither a carried PASS nor a candidate-selected import or policy is accepted.

Every externally selected presentation must be eligible under the actual retained
native2 history, and that history's declared current relying eligibility must be
PASS. An empty presentation inventory is UNKNOWN, never a vacuous closure PASS.
A consistent revoked history may still PASS IDENTITY-2.1 while failing this
current-at-reliance prerequisite. Historical consent reproduction or temporal
HUMAN-7.3 PASS supplies no terminal ALLOW or current identity admission.

The policy independently fixes the scoped public source-key inventory and complete
selected support requirements. Four purposes are mandatory: enrollment authority,
retained assurance, status and exit grant. Every attribute ID relied upon by the
immutable binding requires exactly one attribute requirement; BOT additionally
requires simulation (SIM) scope support. Missing purposes, required attributes, source
keys or evidence are UNKNOWN. Foreign/duplicate relied attributes or unselected
supplied supports refute this finite selection. Certificate presence does not
define the required set. Independently complete application facets/interactions
and their additional obligations remain a separate authority claim.

Each retained support is an Ed25519-signed envelope under an independently
configured public key. The native verifier screens noncanonical/small-order public
keys, then actually verifies each signature through the optional cryptographic
backend. It checks exact source/key, purpose, admitted scope, declared clock,
subject/full record/binding and claim-selection commitments. Both source and
support half-open intervals cover every selected presentation and evaluation time;
exit grants additionally cover the terminal probe time. Issue time is no later
than the earliest selected time. The selected maximum age is enforced separately
at evaluation and every selected presentation; exit grants additionally enforce
it at the terminal probe. Equality to the maximum age is permitted; one additional
microsecond refutes. Times
are nonnegative plain integer microseconds on one declared domain, through 2^63-1;
boolean values are not integers. No runtime clock is read or authenticated.

Support signatures bind canonical source ID, key ID and full payload under the
domain prefix `verifier-current-identity-scoped-support-1` followed by one NUL byte.
The claim-selection digest commits the full exact request except its own evidence,
support-artifact and terminal-probe byte references. Those omitted references
remain independently selected in the full request, native bound proposition and
certificate recheck. This separation avoids recursive signature/artifact hashes;
it does not omit subject, native children, source policy, limits or time bindings.

Each purpose executes an installed exact native witness predicate:

- Enrollment authority checks configured permission to attest `ENROLL_IDENTITY`
  for the actual retained actor, ROLE and original enrollment identifier.
- Assurance supports only
  `native_identity_scope_replay_plus_configured_signature-1`: the exact native3
  byte pin reproduces and the selected configured source authenticates that bound
  assurance method. Another method is UNKNOWN. This proves no measured personhood
  assurance from a scalar label.
- Attribute checks the exact selected typed value and represented subject under
  its configured source signature. Source ID cannot equal the selected actor,
  represented object or root HUMAN, and its public key cannot equal the configured
  holder key. These are configured source/key exclusions; they do not prove
  independent people, causal control ownership or actual attribute truth.
- Status checks ACTIVE at the exact externally selected native2 head/count and
  selected time coverage. It proves a configured status attestation and retained
  eligibility, not real-world log completeness or observed nonrevocation.
- BOT simulation scope checks ACTIVE, the exact selected SIM record and bound
  scope under the configured source. Actual SIM execution/containment is excluded.
- Exit grant binds the installed controller, configured holder/public key and exact
  signed terminal-probe byte reference. Generic `NAMESPACE_ADMIT`, a
  Hash-based Message Authentication Code (HMAC) inventory approval or a capability/result flag
  cannot satisfy any of these purposes.

The configured terminal controller is executable code:
`configured-holder-signature-only-terminal-transition-1`. For a represented HUMAN,
the selected holder is that HUMAN; for AGENT/BOT it is the explicit root HUMAN
under a separately configured withdrawal rule. The retained probe binds exact
identity binding, native2 head, selected clock/time/challenge, controller and claim
selection. Its Ed25519 signature is checked using the externally configured holder
key. Its time cannot precede relying evaluation. The checker then appends a bound
HUMAN exit or root withdrawal/revocation event to a private retained-history copy
and actually runs the installed finite lifecycle interpreter. Consistency must
PASS and relying eligibility at that instant must be FAIL. No issuer
countersignature, fee or separate permission guard is present in this controller.
The retained history is not mutated and the represented entity is not terminated.
This proves only the finite configured transition, never physical/service
enforcement, actual human custody, production availability or one-time consumption.
Probe ordering, expiry, duplicate IDs and all native2 replay bounds still apply.

Public proof mode supports only `complete_retained_public_key_replay-1`: full
native certificates, scoped signed witnesses and signed probe stay in the canonical
evidence bundle, and independently selected policies expose public verification
keys. No secret key is needed for reproduction. Missing bytes or redaction cannot
reproduce a native certificate. Another proof mode is UNKNOWN, including an
unimplemented witness-hiding proof. This local public-key replay property proves
no global artifact availability, privacy/consent admission or safe disclosure.

The request has exactly `schema_version`, `semantic_version`, `coordinate`,
`proposition_digest`, `object_kind`, `subject_id`, `object_digest`,
`collection_digest`, `identity_scope_request`, `identity_lifecycle_request`,
`identity_scope_certificate_ref`, `identity_lifecycle_certificate_ref`,
`binding_digest`, `presentation_inventory_digest`, `clock_id`, `evaluation_at`,
`exit_probe_at`, `exit_challenge_digest`, `exit_probe_ref`, `support_refs`,
`policy_digest`, `evidence_ref`, and `limits`.

Policy fields are `schema_version`, `mechanism_id`, `mechanism_digest`,
`trust_roots`, `max_certificate_bytes`, `identity_scope_policy`,
`identity_lifecycle_policy`, `sources`, `requirements`, `holder_id`,
`holder_public_key`, `public_proof_mode`, and `max_support_age`. Source rows have
`source_id`, `key_id`, `public_key`, `purposes`, `scopes`, `clock_id`, `valid_from`,
`valid_until`. Requirement rows have `requirement_id`, `purpose`, `source_id`,
`claim_id`, and `expected_value`; source/requirement IDs are sorted and unique.
Trust-root labels and configured public keys grant no actual issuer/personhood
authority or source completeness. Unsupported selected purposes stay UNKNOWN.

Evidence `verifier-current-identity-presentation-evidence-1` has exactly
`schema_version`, `identity_scope_certificate`, `identity_lifecycle_certificate`,
`supports`, and `exit_probe`. Child certificates or probe may be null when absent.
Support maps are keyed by independently selected requirement IDs. Source envelopes
have `schema_version`, `source_id`, `key_id`, `payload`, `signature`. Their payload
has `schema_version`, `selection_digest`, `requirement_id`, `purpose`, `source_id`,
`subject_id`, `object_digest`, `binding_digest`, `scope`, `clock_id`, `valid_from`,
`valid_until`, `issued_at`, and `witness`. Probe fields are `schema_version`,
`selection_digest`, `binding_digest`, `head_digest`, `holder_id`, `clock_id`, `at`,
`challenge_digest`, `controller_id`, `signature`; its signature excludes only the
signature field, under `verifier-current-identity-terminal-probe-1` plus one NUL.

Public keys are canonical lowercase 32-byte hex, signatures canonical lowercase
64-byte hex, commitments canonical `sha256:` plus lowercase 64-hex. JavaScript
Object Notation (JSON) is sorted-key compact ASCII (American Standard Code for
Information Interchange) escaped UTF-8 (Unicode Transformation Format, 8-bit);
nonfinite values/duplicate keys are refused
by strict retained parsing. Caller selection/policy data are copied from exact
plain JSON under structural/text bounds before installed-source reads, child calls
or hashing; foreign object callbacks are never admitted. Complete certificate
bytes are rebuilt under independent selection and compared, so rehashed result
claims, missing witnesses, transplanted children and source drift refuse transport.

PASS means this exact finite configured prerequisite conjunction completed through
actual native/cryptographic/controller replay. A known exact binding, signature,
purpose/scope/time, attribute/status or controller refutation produces FAIL.
Missing support/key, unimplemented method/backend, cancellation, failed execution,
admitted exhaustion or unrun descendant produces UNKNOWN unless an evaluated FAIL
already exists. Components retain their own status; errors/cancellation never turn
into PASS, and later uncertainty preserves prior refutation. Malformed external
selection or nonreproducing native certificate refuses transport.

Selected ceilings are 64 supports/requirements, 100,000 prerequisite operations,
4 MiB complete evidence and 8 MiB certificate. One operation enters the evaluator
or starts a retained-companion, support-predicate, support-signature,
probe-predicate, probe-signature, child, eligibility, controller or public-witness
phase; fixed bounded validation
occurs within the phase and is not an instruction count. Source policies admit at
most 16 sources. Child and terminal-interpreter bounds are separately selected and
enforced. Before source reads external capture limits are 100,000 nodes, depth64,
4,096 items per container, 256-bit integers, 4 MiB per string and 8 MiB total encoded
text. Counters are dimensionless; byte counts are encoded bytes, with one MiB equal
to 1,048,576 bytes. These are no central processing unit (CPU) or wall-time guarantee.

Real issuer/personhood/human custody, measured assurance, independent actor/control
ownership and attribute truth, real clock/status/history, physical SIM/exit
enforcement, global availability, general privacy/consent, complete application
facet/interaction authority, whole IDENTITY/object polish and model correctness
remain NOT_ESTABLISHED. Full positive polish additionally requires independently
admitted complete applicability, every actual required native property and
public/disclosure evidence. Finite configured PASS and internal development builds
are not human release acceptance or production promotion.

Retained inspection precedes descendant availability. After a bounded outer
decode, every present native-child, support and probe byte pin and outer record
shape is compared against the external selection. The retained lifecycle payload
is bounded before decoding; its present binding, event and presentation commitments,
selected head/count, supported grammar and plain declared clocks are necessary
checks. A supported binding or presentation permits only its installed declared
predicates; unsupported versions supply no invented authority or lifecycle meaning.
Missing companions provide no completion credit and do not suppress available
independent contradictions.

Every present selected support executes its known source/key, selected subject,
binding, purpose, clock and time predicates and its supported exact witness
predicate before source-key or backend availability decides authentication.
Probe binding, plain time and controller predicates similarly precede holder-key
availability. These declarative checks establish no native replay, authentic
attestation or actual holder control. Actual selected child3 and child2 rechecks
must still PASS; signature verification must actually execute under the selected
purpose-specific source keys and holder key. Complete nonempty retained
presentation eligibility and the fixed terminal interpreter must independently
complete. A failed native child remains a refutation even when a different
descendant is unavailable.
An actually evaluated declared current or presentation eligibility FAIL also
refutes that necessary prerequisite before native-child availability; it grants
no relation or authority completion.

The installed structural evidence schema is
`schemas/identity_presentation_evidence.json`; its exact bytes are included
in the mechanism digest alongside code, this specification, direct dependencies
and both recursive native-child mechanisms. It closes the five-field outer
record and the retained envelope/payload/probe records. It does not define
unsupported purpose-specific witness semantics or authenticate a signature.
Its structural limits mirror installed hard ceilings; smaller selected limits
remain native availability limits. Schema validity supplies no PASS certificate.

Retained bytes are bounded before recursive parsing and canonical hashing:
depth at most 64, 100,000 lexical nodes, 4,096 items per container and 256 bytes
per unquoted atom. The preflight grants no JSON validity; strict decoding still
refuses malformed syntax, duplicate keys and nonfinite numbers. Decoder or
interpreter recursion/overflow, missing execution capacity, cancellation and
backend unavailability yield UNKNOWN unless a refutation has already been
evaluated. Natural absent/bounded UNKNOWN that exactly reproduces remains a
genuine reproduced UNKNOWN.

`IdentityPresentationUnavailable`, an `OSError` subtype, reports
unavailable source, construction or retained checking capacity. Recheck first
refuses independently false carried envelope, result-shape, claim-boundary,
evaluation binding, root/reference, byte-count or certificate-digest claims.
If newly unavailable checking then prevents exact reproduction, recheck raises
that typed exception and never returns a carried outcome. An honest local FAIL
that remains FAIL while execution observations become unavailable is retained
without certifying exact reproduction. A fresh FAIL contradicting carried PASS,
or an ordinary semantic child refusal, remains `IdentityPresentationError`;
ordinary `ValueError` is never broadly converted into capacity unavailability.

`registration()` returns an owned plain copy of the exact existing
proposition. `ROUTE_DESCRIPTOR` names this fixed IDENTITY route and its
public policy/request/build/recheck functions; it confers no admission or
acceptance. Declared microseconds and the 2^63-1 ceiling do not establish TIME
clock semantics, equivalence with a 2^53 range, or physical chronology.
