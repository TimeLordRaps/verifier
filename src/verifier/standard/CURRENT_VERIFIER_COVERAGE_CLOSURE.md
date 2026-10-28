# Current VERIFIER-4.1: coverage closure over a declared finite claim class

Status: experimental, versioned current-object objective. Verifier Standard
(VSTD) specifies the claim; this Python mechanism is one reference checker.
JavaScript Object Notation (JSON) gives canonical retained bytes, Secure Hash
Algorithm 256-bit (SHA-256) names commitments, and a directed acyclic graph
(DAG) orders claim dependencies. Member, node and boundary counts and checking
budgets are dimensionless; evidence and certificate limits are bytes.

## Governing row

`DOMAIN_OBLIGATIONS.md`, VERIFIER-4.1 *Verifier coverage closure*, verbatim:

> Completeness over the declared verifier claim class requires independently checked coverage and counterexample boundaries; one retained decision does not close the class and leaves this profile UNKNOWN.

This objective closes only a **finite declared** claim class. Completeness
beyond that class stays `NOT_ESTABLISHED` in every result.

## Selection

The pair `verifier-current-object-obligations-1` / `VERIFIER-4.1` selects:

- one exact `VERIFIER` namespace record whose payload is `checker_kind`
  `CURRENT_OBJECT_ROUTES` and the sorted unique `[semantic_version, objective]`
  pairs of the declared class, and the singleton typed collection containing it;
- the declared class: one to 512 members, each an `object_id`, `claim_id`,
  semantic version, objective and proposition digest, sorted and unique by
  `(object_id, claim_id)`;
- zero to 64 counterexample-boundary cases, each a sorted unique `case_id`, a
  registered route selection whose objective belongs to the class, exact
  request, policy and certificate digests, and an expected verdict of `FAIL`
  or `UNKNOWN`;
- exact digests of one `CERTIFICATE_DAG.md` bundle, its independently selected
  policy, and the artifact file set holding the member certificates.

## Check

1. The retained VERIFIER record, DAG bytes, file set and boundary bytes must
   equal the selection.
2. **Enumeration.** The class is read from the DAG policy's required objects
   and the approved profiles carried in the bundle, never from the request.
   A missing or unapproved profile is `UNKNOWN`. A declared class that differs
   from the enumerated class is `FAIL`.
3. **Member decisions.** `certificate_dag.assess_certificate_dependencies`
   replays every node through its registered route, checks exact edges,
   rejects cycles with Kahn's algorithm, and qualifies each status by its
   prerequisites. Coverage is then recomputed member by member from the node
   records: a member is covered only by direct `PASS`, qualified `PASS` and
   reason `NATIVE_REPLAY`. A member `FAIL` is `FAIL`; a missing or undecided
   member is `UNKNOWN`.
4. **Boundaries.** Every class objective needs at least one boundary case,
   otherwise `UNKNOWN` (`COUNTEREXAMPLE_BOUNDARY_MISSING`). Each case is
   replayed through its route. A replay equal to the expected verdict passes.
   A `PASS`, a route refusal, or `FAIL` where `UNKNOWN` was expected is `FAIL`.
   `UNKNOWN` where `FAIL` was expected, an unavailable checker, or missing case
   evidence is `UNKNOWN`.
5. Any failure gives `FAIL`; otherwise any unknown gives `UNKNOWN`; otherwise
   `PASS`. Node, member and boundary budgets are checked before native replay,
   and exhausting them is `UNKNOWN`.

A single retained decision never passes: a class with no boundary case is
`UNKNOWN`, so a `PASS` always rests on at least one member decision and one
independently replayed counterexample boundary per objective.

## Verdicts and result

`PASS` sets `declared_class_coverage_closure` to `PASS`. Every result carries
`completeness_beyond_declared_class`, `declared_class_authority`,
`class_wide_soundness`, `checker_correctness`, `whole_verifier_closure` and
`object_profile_conformance` as `NOT_ESTABLISHED`. Malformed or substituted
requests, policies or certificates raise `VerifierCoverageClosureError`
(`REJECTED`).

## Differences from VERIFIER-2.1

VERIFIER-2.1 checks that the installed SIM checker reproduces independently
selected expected outcomes on finite cases: one checker, its answers. This
objective checks a class of claims across registered routes: that the class
declared is the class the retained profiles enumerate, that each member has a
replayed decision, and that the checkers reject declared counterexamples. It
does not re-derive any member's verdict.

`BOUNDED_COMPLETENESS.md` (`interoperability/bounded_completeness.py`) is
related but distinct. That direct-module experiment asks whether every member
of an externally source-grounded finite denominator has a decisive replayed
disposition. It is not a registered current-object route, and it has no
counterexample boundaries or DAG-profile enumeration. This objective does not
reuse or extend its denominator grounding.

## Recursion

Neither a class member nor a boundary case may have objective `VERIFIER-3.1`
or `VERIFIER-4.1`; the request rejects it and a retained profile containing
one is `FAIL`. A closure started while another VERIFIER-4.1 closure is active
on the same thread is `UNKNOWN`.

## Exclusions and invalidation

No claim is made about members outside the retained selection, the authority
or adequacy of the declared class, any checker's correctness on other inputs,
or privacy, consent, governance, security, physical facts or safety. The
policy pins this module, `certificate_dag.py`, `current_object_routes.py`,
the core certificate, evidence, receipt and namespace modules, the shared
selection helpers, `NAMESPACE_OBJECTS.md`, `CERTIFICATE_DAG.md` and this
specification; a change to any of them, including registering another route,
invalidates the selected policy.
