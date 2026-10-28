# Selected ten-tier VERIFIER-6.1: composed signed association

Status: experimental direct-module contract. Verifier Standard (VSTD);
JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).
Unicode Transformation Format, 8-bit (UTF-8) encodes text. Byte limits count
octets. Generation, counts and sequence positions are dimensionless. Session,
process and operation identifiers are selected opaque labels, not observations.

The pair verifier-current-ten-tier-object-obligations-1 / VERIFIER-6.1 selects
one finite security proposition. It composes existing native
verifier-current-object-obligations-1 / VERIFIER-9.1 typed-subject association
and RECEIPT-9.2 selected issuer-key signature. Their native wire identifiers,
propositions, policies and coordinates retain their meanings. No nine-tier
coordinate, legacy certificate, public route or full application profile is
renamed or automatically promoted.

## Proposition and external selection

PASS requires both exact externally selected native certificates to replay PASS.
The association names the selected VERIFIER identifier and canonical record
digest and binds the selected context digest. Its selected chain entry carries
exact canonical typed-subject intent. The issuer-key certificate authenticates
that same selected chain certificate under its independently selected key.

Before either native recheck, missing-child handling, selected cancellation or
signature-backend outage handling, the composition checks:

1. Source-free closed validation checks the selected child family, coordinate,
   proposition, represented kind, complete policy/request fields and bindings.
   The association names this exact VERIFIER subject and context; its selected
   chain sequence has the native finite plain-integer representation.
2. The children's complete chain requests are canonically equal, their complete
   chain policies are canonically equal, and their selected raw chain-certificate
   digests are equal. A shared tip, issuer label or neighboring subject is
   insufficient.
3. Every available child certificate reproduces its externally selected raw-byte
   digest, canonical envelope, complete request/policy/proposition/mechanism
   bindings, and retained evidence commitment. Present native evidence is
   examined for independently decidable subject, message and signed-intent
   contradictions before an unavailable peer can stop further work.
4. For positive composition both native evidence bundles physically retain the exact chain-certificate
   text; its UTF-8 encoding, decoded from each outer canonical base64 certificate,
   is byte-identical and hashes to the common externally selected digest.
   A declaration or a repeated digest cannot replace this retained-byte equality.
   Available retained chain bytes are compared before replay. Missing peer bytes
   prevent PASS but do not prevent a present usable native child from refuting
   its own independently selected prerequisite.
5. The selected context and retained context are equal. Native association
   intent binds the canonical SHA-256 digest of the complete context below.

The context has exactly:

    schema_version = verifier-ten-tier-verifier-security-context-1
    subject_id object_digest artifact_digests instruction_digest
    context_revision_digest generation operation_id session_id process_id
    authority_policy_digest

Artifact digests are one to 256 sorted unique canonical sha256: commitments.
Generation is a plain integer from zero through 2^53-1; booleans are refused.
The other digest fields use the same canonical commitment format. Identifiers
are nonempty text of at most 256 UTF-8 bytes without control characters.
The context's subject identifier and record digest must equal the outer selection.
The authority-policy digest names selected bytes, not their real-world authority.
The checker does not invent generation, process, instruction, artifact or provenance
values from a certificate.

## Closed wires and interface

Direct import: verifier.domains.contracts.verifier_composed_security.
Policy, request, evidence, certificate, context and selector use distinct
verifier-ten-tier-verifier-...-1 identifiers defined in that module. Native
closed readers remain responsible for their child dialects; field resemblance
never selects an objective. Unknown fields and non-plain selection values are
refused. No external executable, locator, callback or producer-controlled
checker is invoked.

The policy has exactly schema_version, mechanism_id, mechanism_digest,
trust_roots, max_certificate_bytes, association_policy, authenticity_policy.
The complete native policies are independently selected. Trust-root strings
label selections and authenticate no selector.

The request has exactly schema_version, semantic_version, coordinate,
proposition_digest, object_kind, subject_id, object_digest, context_binding,
association_request, authenticity_request, association_certificate_digest,
authenticity_certificate_digest, evidence_ref, policy_digest,
max_evidence_bytes, cancelled. Each native request is separately selected in
full. The selected cancellation flag is a plain boolean, remains bound to the
request and never authorizes an action. A changed flag invalidates an old outer
certificate's exact selection.

Evidence has exactly schema_version, context_binding, association_certificate,
authenticity_certificate. Each child certificate is canonical base64 of exact
raw bytes, or explicit null for unavailability. Omitted keys, empty/noncanonical
base64, extra fields or substituted bytes are contradictions. A whole evidence
bundle may be unavailable.

verifier_composed_security_policy and verifier_composed_security_request capture
selections. build_verifier_composed_security_certificate retains and checks
evidence. recheck_verifier_composed_security_certificate requires the independently
selected complete request and policy and reconstructs the whole canonical
certificate. Certificates cannot choose their own denominator, context, issuer
key, native selections or acceptance policy.

## Selector-first execution, bounds and verdicts

The checker retains the exact captured external request in a distinct closed
selector record, verifier-ten-tier-verifier-security-selection-1, with exactly
schema_version and independently_selected_request. This is selection input, not
an observation, native witness, authority record or synthesized provenance.
Its bytes are passed through BoundProposition, EvidenceStore and
VerificationSession first. Actual candidate evidence is a separate second
content-addressed input only when supplied. The bound parameters commit the
complete request digest and candidate-evidence presence. Selector and candidate
identities must differ. Missing candidate bytes are never inferred from selection.

Selection capture admits exact built-in dictionaries, lists, strings, integers,
booleans and null; it refuses foreign containers and values before canonical
operations. String character counts are checked against the remaining text
allowance before encoding; encoded bytes retain the same tighter total budget.
Identifier character counts are checked before stripping or encoding.
Bounds are one mebibyte (1,048,576 bytes) of captured selection,
50,000 visited values, 4,096 items per container, nesting depth 48 and integers
of at most 4,096 bits. The selector wrapper has a separately accounted exact
byte size. Generation retains its tighter bound.

The fixed session ceiling is two inputs and the selector's byte size plus
8 mebibytes of candidate evidence. Independently selected candidate evidence
may have a smaller positive byte allowance, checked after selected contradictions.
Retained decoding preflights depth 48, 50,000 containers and numeric tokens of
at most 1,234 consecutive digits before recursive JSON parsing. The parent
certificate ceiling is 16 mebibytes. Each native child certificate is at most
8 mebibytes and its evidence at most 4 mebibytes; the common chain certificate
is at most 2 mebibytes and chain evidence at most 1 mebibyte. Selected native
policies can tighten those limits; no parent limit enlarges them. These local
input bounds do not attest machine resources or process isolation.

Decidable selected or retained contradictions give FAIL before missing evidence
or selected cancellation. Capacity can prevent inspection of unexamined bytes;
an unavailable tail supplies no positive result. After binding preflight and
comparison of available retained chain bytes, every usable available native
child is replayed even if its peer is absent or UNKNOWN. Missing or unusable
children contribute UNKNOWN; complete common-chain equality remains required
for PASS.
Aggregation is FAIL > UNKNOWN > PASS. A native refutation survives a later
native outage or cancellation. Installed source reads and the native policy
admission inside recheckers occur only after this preflight. The outer builder
and rechecker preserve the external mechanism pin without selecting a replacement;
only the explicit policy constructor offers a fresh installed pin. A changed
available pin refutes that external selection; a missing pinned source prevents
positive admission and gives UNKNOWN unless a known contradiction gives FAIL.
Cancellation raised during native replay is
UNKNOWN for that child; process termination produces no result.
ImportError and MemoryError raised by a native rechecker or delayed source
admission are typed dependency/capacity outages. They become UNKNOWN locally
before aggregation and cannot erase an independently observed FAIL.
Other unexpected native support exceptions are also fenced as UNKNOWN locally;
explicit native structural refusals remain FAIL. A support crash establishes
no unsupported child claim, and process termination produces no result.

Missing required bytes, selected cancellation without an observed contradiction,
unsupported checking capacity and honest source/signature-backend unavailability give
UNKNOWN. A fresh UNKNOWN certificate can reproduce exactly.
Successful exact replay explicitly returns `replay_status=REPRODUCED` as
recheck metadata. This field is required by the selected native route; it is not
a carried certificate claim or an implicit missing-field default. If the backend later
cannot check a previously issued certificate, replay preserves selected bindings,
claim-limit invariants and decidable carried-result facts, and returns UNKNOWN
with replay_status=UNAVAILABLE; it neither reproduces the carried positive result
nor calls honest loss of capability a forgery. Changed signatures, subjects,
requests, policies, certificates or canonical context cannot be repaired by
rehashing an outer envelope. Malformed outer selections and substituted outer
certificates are refused without issuing a computational PASS.

## Pinning, retention and admission

The mechanism digest binds this module and specification, native namespace and
ten-tier progression specifications, shared canonicalization, evidence, receipt,
namespace, bounded-checking and selection source, plus the complete native
association, issuer-key and chain mechanism digests and their transitive pinned
sources/specifications. Changed bytes require fresh independently selected
policies and certificates. Optional cryptographic verification remains the
existing native dependency; this module adds no required runtime dependency.
Source pinning alone proves neither loaded-code authenticity nor correctness.
No source-free correctness, whole-system corrigibility or complete security proof
is supplied by this finite contract.

The result's selected_signed_association may be PASS for this exact finite
proposition. composed_security_admission remains UNKNOWN in every result.
Whole security admission, full object-profile conformance, authority, key custody,
trusted time, live revocation, challenge/context consumption, actual execution,
human acceptance, production admission and disclosure authority remain
NOT_ESTABLISHED. Signature validity under a selected key does not authenticate
a person, authority-policy applicability, public origin or hardware observation.

Canonical certificates retain their complete selector and candidate witnesses.
Publication needs separate disclosure authority; redaction cannot preserve the
complete canonical claim. Dynamically generated test keys support local fixtures
only. Real production admission must independently select authorized issuer
keys, authority and current evidence and can never be inferred from a test-key
fixture or a finite PASS. This contract supplies no production admission.
