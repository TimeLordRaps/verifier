# Current RECEIPT-4.1: closed, acyclic declared receipt prerequisite cone

Status: experimental, versioned current-object objective. Verifier Standard
(VSTD) specifies the claim; this Python mechanism is one reference checker.
JavaScript Object Notation (JSON) gives canonical retained bytes and Secure
Hash Algorithm 256-bit (SHA-256) names commitments. Byte limits measure exact
retained bytes. Counts and checking budgets are dimensionless.

## Grounding

The CLOSURE rationale for RECEIPT names refutable transformation closure,
prerequisite receipt chain validation and complete proof bounds. This
objective selects **prerequisite receipt chain validation** alone, in its
declared form. The VSTD-1 claim receipt has no receipt-to-receipt field, and
`NAMESPACE_OBJECTS.md` says relationships inside a payload are not silently
interpreted as composition dependencies. So the relation used here is the
mechanism-defined `prerequisites` list of the `RECEIPT` namespace record
admitted by `RECEIPT-3.1` (sorted, unique, bounded identifiers), following
the `EVENT-3.1` precedent of a declared prerequisite list. A declared
prerequisite is record content: it is not proof that one receipt's claim
actually depends on, derives from or was caused by another.

## Proposition

For one externally selected root `RECEIPT` record and an externally selected,
subject-sorted list of one to 64 children, where each child names the digest
of an exact `RECEIPT-3.1` request, policy and retained certificate:

1. Every retained child request and policy hashes to its selection and names
   the selected subject, `verifier-current-object-obligations-1`,
   `RECEIPT-3.1` and kind `RECEIPT`; every retained child certificate hashes
   to its selected digest.
2. Every child certificate is rechecked against the installed `RECEIPT-3.1`
   mechanism with its retained request and policy. If any child does not
   replay or replays `FAIL`, the parent is `FAIL`. Otherwise, if any child is
   `UNKNOWN`, the parent is `UNKNOWN`.
3. The root subject is one of the children and its retained record digest
   equals the request's object digest.
4. Starting from the root, every identifier in a reached child's declared
   `prerequisites` names a selected child, and every selected child is
   reached. A missing prerequisite or an extra unrelated child is `FAIL`.
5. Kahn's algorithm orders every child so that each prerequisite precedes
   its dependants. A cycle, including a self-reference, is `FAIL`.

Membership is checked through **child certificates, not a re-run**. Each
member's statics result is separately selected, retained and replayable on
its own, and the parent request commits to each child's request, policy and
certificate digest. The recheck rebuilds each child certificate from its
retained evidence, so the parent never trusts a stored child verdict, and a
child `UNKNOWN` or `FAIL` propagates instead of being re-decided under the
parent's limits.

An exhausted byte, item, operation or child-count limit, a child certificate
beyond the `RECEIPT-3.1` certificate ceiling, or the recursion ceiling, is
`UNKNOWN`. A malformed request, policy, child list (unsorted, duplicated,
empty or over 64) or limit override, or a substituted certificate, is
`REJECTED`: `ReceiptPrerequisiteClosureError` is raised before replay.

## Differences from RECEIPT-9.1 and RECEIPT-9.2

`RECEIPT-9.1` (receipt chain) checks a linear, domain-separated link hash
chain over opaque receipt bytes ending at a selected tip. This objective
checks a declared, possibly branching prerequisite relation between
namespace records whose receipt bytes each pass `RECEIPT-3.1`; it computes no
link hash and asserts no order of creation. `RECEIPT-9.2` (receipt
authenticity) checks an issuer signature; this objective checks none.

## What PASS does not establish

`PASS` means only that the selected children form a closed, acyclic declared
prerequisite cone rooted at the selected record, and that each member's
retained receipt bytes satisfy the `RECEIPT-3.1` predicate. It does **not**
establish real dependency, causality or derivation between receipts,
transformation closure between member claims, completeness of any proof
bound, claim truth, audit validation replay of any member (`RECEIPT-2.1`),
external referent bytes, hash-chain continuity, issuer authenticity, the
whole RECEIPT closure tier or object-profile conformance. Privacy, consent,
governance, security, authority and publication are not claimed; their
result fields remain `NOT_ESTABLISHED`.

The parent certificate retains every exact child request, policy and
certificate as evidence, plus the parent request and replay result. Public
release of retained contents requires separate disclosure authority. Changed
parent or `RECEIPT-3.1` source, the installed namespace or receipt model,
either specification, retained bytes, child selection or policy invalidates
the pinned mechanism digest and therefore the certificate.
