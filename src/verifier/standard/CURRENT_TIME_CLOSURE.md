# Current TIME-4.1: selected declared-clock inventory closure

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256); directed acyclic graph (DAG). This versioned current-object predicate closes one
externally selected finite sample inventory on one declared microsecond clock.
Sample counts and checking budgets are dimensionless. It does not establish
physical time, authoritative inventory completeness or whole TIME-tier closure.

`verifier-current-object-obligations-1` / `TIME-4.1` selects this predicate.
Its child is the exact independently selected `TIME-2.1` request, policy and
certificate, retained and freshly replayed. The parent and child must name the
same TIME identifier, record digest and complete collection digest. The child
must replay PASS. A carried PASS or another passing child cannot replace it.

The parent additionally selects the complete canonical inventory digest, a
positive inventory count, root and terminal sample identifiers, the declared
clock, `span_start_us`, `span_end_us` and `cutoff_us`. These are consumer inputs,
not requirements chosen from the certificate. The retained inventory has exactly
`schema_version`, `subject_id`, `object_digest`, `collection_digest`, `clock`,
`unit`, `span_start_us`, `span_end_us`, `cutoff_us`, `root_sample_id`,
`terminal_sample_id` and `samples`. Its schema version is
`verifier-current-time-closure-inventory-1`; its unit is `microsecond`.
Each sample has exactly `id` and `at_us`. Inventory instants must be nondecreasing,
as required by the selected TIME-2.1 child; equal instants remain allowed. Identifiers are nonblank plain strings
of at most 256 characters; instants are plain integers from zero to 2^53-1.
Boolean values are not integers. Inventory sample identifiers are unique.

The inventory must reproduce its external digest and all selected metadata.
The child's actual TIME payload must agree with the selected clock, unit and
span. The child's retained ordered sample rows must equal the complete selected
inventory rows byte for byte under canonical JSON. Its count must equal the
selected count; its first and last identifiers must equal the selected root and
terminal sample identifiers. These identifiers mark sample-list endpoints, not
certificate-DAG roots, events or physical start/stop observations.

The selected cutoff equals `span_end_us`, the **exclusive** upper boundary.
Every inventory sample is within `[span_start_us, span_end_us)`. No sample at
the cutoff is allowed. The first sample need not occur at the span start; the
last need not immediately precede the cutoff. Equal instants remain permitted,
as in TIME-2.1. This is exact selected sample-inventory closure, not interval
coverage, sampling density or strictness. TIME-3.1 stays a separate predicate.

Parent evidence has exactly `schema_version`, `child_request`, `child_policy`,
`child_certificate` and `inventory`, with the child certificate in canonical
base64. A null `inventory`, `child_request`, `child_policy` or
`child_certificate` explicitly means that retained support is unavailable;
missing or extra top-level fields remain malformed evidence. The parent request binds the child request, policy and exact certificate
digests, inventory selection, parent evidence reference, policy and finite limits.
The schema identifiers are `verifier-current-time-closure-request-1`,
`verifier-current-time-closure-policy-1`, `verifier-current-time-closure-evidence-1`
and `verifier-current-time-closure-certificate-1`. Native request validation and
complete certificate-byte reconstruction are authoritative; field resemblance is
not dispatch or computational support.

Missing evidence, null retained support, an UNKNOWN child, unavailable checker
inputs and selected capacity exhaustion give UNKNOWN. Independently checkable
inventory selection/count/duplicate/order/boundary/endpoint contradictions are
inspected before completing an unavailable child; an unavailable child cannot
erase those FAILs. Each present child component is checked for exact selection
and shape before absence in another component can give UNKNOWN. Present
request/subject, policy or certificate/base64/digest contradictions remain FAIL
even if another child component is null. A genuinely replayed child FAIL also dominates a missing
inventory. Reaching a checking bound can prevent inspection of later predicates. A failed child, mismatched exact child tuple,
inventory substitution, inspected omission/extra/reordering, duplicate sample,
wrong root/terminal or contradictory clock/span gives FAIL. Malformed external
requests/policies/certificates are refused before a computational verdict.
Resource bounds may prevent reaching a later contradiction; unavailable capacity
does not certify uninspected material. No later UNKNOWN changes an observed FAIL.

Parent ceilings are 100000 charged input-traversal/comparison operations, 4096
items per retained container, 8 mebibytes of evidence, nesting depth 48 and a
16-mebibyte certificate. A mebibyte is 1,048,576 bytes. Decoder preflight bounds
nesting and decimal integers to 1234 digits before recursive parsing, including
the child certificate and its retained evidence. Parent certificate input gets
preflight under the fixed decoder ceiling before recursive parsing. Decoder
recursion/overflow exhaustion remains unavailable, not a semantic refutation. The byte
bound also limits that linear preflight; it is not a charged comparison count.
The exact child retains its independently selected native bounds. Build refuses
evidence above the fixed ceiling; selected evidence exhaustion yields UNKNOWN.
`TimeClosureUnavailable` is an `OSError` subtype for unavailable external
certificate-input checking and preserves the current route UNKNOWN category;
`TimeClosureError` remains the semantic/selection refusal category.

The retained parent physically embeds the exact TIME-2.1 child certificate. A
canonical dependency graph must represent that exact child under its own
obligation and context; this native wrapper alone does not add or couple DAG nodes. Shared exact child evidence can serve independently selected
nodes, but different request/policy/certificate contexts cannot be merged by label.
The selected inventory's completeness authority, source-to-native mapping,
facet/interactions and complete application applicability profile remain separate.
An adversarial selector can choose a truncated inventory; this predicate does not
authenticate the selector or discover unrecorded physical samples/events.

Physical clock identity, calibration, skew, wall-clock truth, synchronization,
physical causality, EVENT-to-sample binding, continuous temporal coverage, minimum
spacing, actual termination, append-only history, whole closure-tier conformance,
privacy, consent, governance and security remain NOT_ESTABLISHED. TIME, EVENT and
cross-clock interaction claims require separately specified predicates and exact
prerequisites; strict timestamps do not supply them.

The certificate retains the full inventory and child evidence. Canonical emission
with a retained witness withheld must be refused. Public disclosure authority and
public-witness availability/checkability are separate requirements. A hash or
signature alone supplies neither a witness nor its truth. Complete positive
issuance additionally requires independently admitted facet/applicability and
interaction requirements through the canonical certificate dependency graph;
this single certificate does not establish such completeness or issue clearance.
