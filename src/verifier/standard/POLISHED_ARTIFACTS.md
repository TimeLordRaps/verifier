# Verifier Standard (VSTD) polished-artifact admission

> **Acronyms:** command-line interface (CLI); JavaScript Object Notation (JSON);
> Secure Hash Algorithm 256-bit (SHA-256); Unicode Transformation Format, 8-bit (UTF-8);
> Verifier Standard (VSTD).

**Status:** experimental admission assessment versions 1 and 2; polished-artifact issuance
is not implemented. No existing object is promoted by this specification.

## Meaning and present implementation

A **polished artifact/object** closes every declared applicable computational,
authority and relational object certificate, its wiring and dependencies, through
the nine distinct meta-tiers in [META_TIERS.md](META_TIERS.md). SECURITY is tier 9;
GOVERNANCE remains tier 8. Every internal objective needs its own proposition,
mechanism, scope and refutable evidence. A complete table of tier names is not a
complete objective inventory. Inapplicability requires independently admitted
evidence; an author cannot waive an obligation by labeling it not applicable.

Verification serves as a meta-programming language here by describing and checking
typed representations and their evidence obligations above the represented programs.
This is a bounded architecture, not universal correctness or proof that all relevant
properties of a real-world system have been discovered.

The implemented gate inventories all supplied objects and tier declarations, checks
finite typed composition, and replays the registered installed current-object objectives
under external selection. It reports native PASS, FAIL and UNKNOWN separately.
Exhaustive objective-inventory closure, authenticated inapplicability and authority,
and private-witness public proofs are not registered mechanisms in this admission
version. Consequently its aggregate cannot be PASS and `polished` is always false.
This is an executable assessment of prerequisites and gaps, not completed polishing.

## Retained inputs

`verifier-polish-bundle-1` has exactly `schema_version`, `objects`, and `certificates`.
`objects` is a nonempty list of canonical namespace records with exactly `object_id`,
`kind`, `payload`, and `operands`. `certificates` maps canonical `sha256:` digests to
the complete UTF-8 certificate text. The digest binds the exact encoded certificate
bytes; parsing and rewriting the certificate is not an equivalent binding.

`verifier-polish-request-1` is selected separately by the consumer and has exactly
`schema_version`, `root_id`, `collection_digest`, `bundle_digest`, and `requirements`.
The bundle digest binds exact file bytes. The collection digest uses the namespace
composition mechanism. The root must belong to that complete supplied collection.
Every supplied object, including non-root dependencies, needs a row at tiers 1–9.
Missing rows are explicit UNKNOWN gaps. Selection and digest binding do not authenticate
the consumer or prove that its chosen inventory is exhaustive.

Each requirement has exactly `object_id`, integer `tier`, `applicability`, `rationale`,
and `objectives`. Applicability is REQUIRED, NOT_APPLICABLE or UNKNOWN. The rationale
is nonblank bounded text. Non-required rows cannot carry objective assertions and
cannot discharge closure. Duplicate object-tier rows refuse admission.

Each objective has exactly `semantic_version`, `coordinate`, `request`, `policy`,
and `certificate_digest`. The coordinate must match its row's tier and represented
kind, except generic OBJECT objectives may describe another admitted kind. Native
requests and policies are external selections, not values selected from certificates.
Each registered route additionally binds its subject record and, where applicable,
the entire selected collection. Duplicate objectives refuse admission. Unknown
mechanisms remain UNKNOWN; a carried PASS or signature never supplies a checker.

Bounds are 32 mebibytes per bundle, 4 mebibytes per request or stored assessment,
64 objects, 64 objectives, and 32 mebibytes of cumulative certificate replay. One
mebibyte is 1,048,576 bytes. All row and workload bounds precede native replay.
Malformed, substituted, over-bound or conflicting input yields FAIL. Missing
retained evidence or mechanisms yields UNKNOWN. Native results remain scoped to
their own propositions; native failure yields aggregate FAIL.

## Explicit version 2 capacity and shared evidence

`--contract-version 2` selects `verifier-polish-bundle-2`,
`verifier-polish-request-2`, `verifier-polish-assessment-2` and
`verifier-polish-replay-2` together. The Python assessment and rechecker select the
same contract with `contract_version="2"`. Omission retains version 1, including
its limits and failure behavior. Mixed identifiers refuse admission. Version 2
retains the requirement rows, native selections, subject bindings and aggregate
UNKNOWN boundary; capacity is not objective-inventory closure or issuance.

The version 2 request adds exactly `limits`, a complete map of independently
selected positive plain integers. Boolean values are not integers in this contract.
Each value must be at most its implementation ceiling:

| Field | Ceiling | Work charged |
|---|---:|---|
| `bundle_bytes` | 67,108,864 | Exact retained bundle bytes |
| `request_bytes` | 8,388,608 | Exact request bytes, including its limits |
| `objects` | 4,096 | Supplied namespace records |
| `requirements` | 36,864 | Supplied object/tier rows |
| `objectives` | 8,192 | Selected numbered objectives |
| `certificates` | 8,192 | Unique retained certificate entries |
| `evidence_bytes` | 67,108,864 | Decoded shared payload bytes, once per digest |
| `certificate_bytes` | 67,108,864 | Sum of reconstructed or direct certificate bytes |
| `replay_bytes` | 268,435,456 | Certificate bytes for every selection, including repeats |
| `composition_operations` | 1,000,000 | Reserved allowance for bounded composition traversal |
| `composition_payload_bytes` | 67,108,864 | Sum of canonical namespace payload bytes |
| `composition_reference_bytes` | 16,777,216 | Canonical identifiers, operand roles and targets |
| `output_bytes` | 33,554,432 | Reserved canonical assessment size; minimum 4,096 |

Counts are dimensionless. Byte fields use bytes, not character counts. Request
transport exceeding its fixed ceiling refuses parsing. A valid selected capacity
that cannot discharge the workload yields UNKNOWN with
`reason=RESOURCE_LIMIT_EXCEEDED` and a fixed `exhausted_resource` name, before any
native objective invocation. The bounded composition traversal also finishes
before those invocations. Malformed or known substituted bytes yield FAIL.
Exhausted capacity may prevent inspection of later input; UNKNOWN asserts no
validity for that uninspected material. Missing certificates remain UNKNOWN.

The bundle adds exactly `evidence_payloads`, mapping exact `sha256:` byte digests
to canonical base64 strings. No unreferenced entries are allowed. Each certificate
entry keeps its original exact-byte digest as key and selects one encoding:

- `{"encoding":"utf8","text":...}` retains the original certificate text.
- `{"encoding":"shared-canonical-json","envelope":...,"evidence_refs":[...]}`
  retains a canonical certificate without its `evidence_payloads` field. References
  must be sorted, unique digests in the shared map. Reinsert the exact base64 map
  under that field, then encode the certificate canonically.
- `{"encoding":"shared-text-json","envelope":...,"evidence_ref":...}` retains
  a canonical certificate without its `evidence` field. Decode the selected shared
  bytes as UTF-8, reinsert the exact string under `evidence`, then encode canonically.

The removed field must be absent from the envelope. Missing, duplicate or replaced
references, noncanonical base64 and reconstructed certificate-digest mismatches
refuse admission. Reconstruction must reproduce the original certificate bytes;
it neither rewrites native commitments nor supplies a native policy from evidence.
The native checker still checks its complete original certificate. Certificates
that do not support either shared representation use `utf8`.

`resource_usage` reports admitted byte/count charges. Its composition operation
value is the reserved selected allowance, not a measured operation count. Its
output value is a conservative reservation: 4,096 bytes plus canonical missing-row
bytes and, for each selection, 1,024 bytes plus the canonical object identifier,
coordinate, semantic version and certificate-digest record. This reservation is
checked before replay and includes result metadata. `output_bytes` bounds the
canonical assessment representation; pretty-printed command output adds formatting.
Shared retention saves storage only where the selected certificates actually share
bytes; it never discounts reconstructed or repeated native replay workload.

```sh
vstd polish assess bundle-v2.json --request request-v2.json --contract-version 2 --json
vstd polish check assessment-v2.json --bundle bundle-v2.json --request request-v2.json --contract-version 2 --json
```

## Assessment and independent replay

```sh
vstd polish catalog --json
vstd polish assess bundle.json --request request.json --json
vstd polish check assessment.json --bundle bundle.json --request request.json --json
```

The gate reads selected files and prints JSON or text. It does not publish, freeze,
seal, thaw, execute manifest commands or write a result file. Filesystem paths can
refer to network-backed storage; no network client or hosted availability check is used.

The assessment identifier is `verifier-polish-assessment-1`. Every result contains
`schema_version`, `status`, `polished`, `objective_inventory_closure`, `claim_boundary`,
`mechanism_digest` and `assessment_digest`. Successful input parsing additionally
reports exact input digests, root and collection, composition status, tier-inventory
status, applicability status, missing rows, objective results and remaining gates.
Malformed inputs have `reason=INVALID_OR_SUBSTITUTED_INPUT`. Unavailable files yield
an UNKNOWN diagnostic with `reason=INPUT_UNAVAILABLE`; that diagnostic is not a
replayable assessment and carries no assessment digest.

The mechanism digest binds installed assessment code, helper code and this specification.
The assessment digest hashes its canonical JSON before adding `assessment_digest`.
Neither digest authenticates historical execution. `polish check` recomputes the whole
result and compares canonical bytes; rehashing a forged status cannot pass. Its output
identifier is `verifier-polish-replay-1`, with REPRODUCED or REJECTED `replay_status`.
Exit 0 means catalog success; assessed or reproduced UNKNOWN exits 2, and FAIL or
replay rejection exits 1. There is no positive polished-artifact exit in version 1.

`applicability_status=PASS` means every required declaration is present and none is
waived; it does not establish the completeness or correctness of applicability.
`tier_inventory_status=PASS` means the declared object-by-tier rows are complete,
not that every internal objective is implemented or passes.

The catalog's slot inventory preserves its compatibility `coordinate` and
`mechanized_route` fields and adds `registered_objectives` for every installed
numbered objective in that slot. OBJECT facets therefore retain both `OBJECT-1.1`
and `OBJECT-1.2`. `coordinate_role` distinguishes a primary registered objective
from an unregistered slot placeholder; neither spelling establishes complete
coverage. `objective_inventory_closure` remains NOT_ESTABLISHED. Slot rationales
are planning context, not authoritative lists of numbered requirements, as
`rationale_status=PLANNING_CONTEXT_NOT_NUMBERED_REQUIREMENTS` records.

## Public checkability and lifecycle

A native replay may consume retained private witness bytes. Its observation is
`RETAINED_CERTIFICATE_REPLAYED_LOCALLY`; public checkability stays NOT_ESTABLISHED.
A public proof interface must separately bind the exact claim, protected evidence,
predicate, mechanism, public commitments, output, trust assumptions and limits.
Omitting the witness, publishing a digest, or attaching a signature does not establish
that an outsider can check the underlying proposition. Raw witnesses and exception
details are not echoed in assessments; output suppression alone is not a privacy proof.

Polished, frozen, sealed, thawed and published are distinct states. Freeze preserves
bytes; a seal closes the declared freeze under its mechanism; thaw creates a descendant
whose changed bindings need new assessment. Publication is a separately authorized
transport action. See [ARTIFACT_CONTROL.md](ARTIFACT_CONTROL.md).

ClaimGarden's legacy gated intake and its PENDING_REVIEW result do not admit polished
status. This assessment contract supplies no positive host admission: a future
versioned adapter must verify complete closure, public checkability and current
authority against its own independently selected policy before promotion.
