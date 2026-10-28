# Current BENCH-2.1: declared attempt bounds and best-of-N selection

Status: experimental, versioned current-object objective. Verifier Standard
(VSTD) defines the claim language; the Python module is one reference checker.
JavaScript Object Notation (JSON) gives canonical retained bytes and Secure Hash
Algorithm 256-bit (SHA-256) names commitments. BENCH is the benchmark
specification graph object kind. Attempt counts, attempt bounds, scores, list
positions and operation budgets are dimensionless. Evidence and certificate
bounds are measured in bytes.

The pair `verifier-current-object-obligations-1` / `BENCH-2.1` answers the
dynamics question "Which transitions and interactions can its facets undergo?"
for one numbered obligation row of `DOMAIN_OBLIGATIONS.md`, quoted verbatim:

| BENCH-2.1 | Attempt policy | Repeated attempts and best-of-N selection are declared and bounded per problem. | none | none |

This objective decides a bounded strict subset of that row on retained bytes
only: the declaration and the per-problem bound are checked against the
retained attempts, and the declared best-of-N choice is recomputed exactly. The
row text is also carried in the registration, so changing it changes the
proposition digest; `DOMAIN_OBLIGATIONS.md` is bound into the mechanism digest.

Proposition: the externally selected exact BENCH namespace record occurs in the
selected finite typed collection and commits to a retained finite problem
declaration giving each problem a positive maximum attempt count, and declares
best-of-N selection under a named supported metric with
earliest-retained-attempt tie breaking; over the retained attempts every
attempt identifier is unique and names a declared problem, no problem has more
attempts than its declared maximum, every problem with an attempt has exactly
one selection and no selection names a problem without attempts, and each
selection names the earliest retained attempt with the best recomputed score
for its problem and records exactly that score.

The BENCH record payload has exactly `scope` (`retained-attempt-policy`),
`selection` (`best-of-n`), `metric`, `tie_break`
(`earliest-retained-attempt`) and `problems_digest`, which commits to the
retained problem list. Supported metrics are `exact-match`, scoring 1 when the
canonical JSON bytes of the answer equal those of the reference and 0
otherwise, maximised; and `absolute-error`, the absolute integer difference,
minimised and decided only over integers of magnitude at most 2^53 - 1.
Inputs have exactly `problems`, `attempts` and `selections`. A problem is
`{"id","reference","max_attempts"}`; an attempt is `{"id","problem","answer"}`
and its position in the retained list orders ties; a selection is
`{"problem","attempt","score"}` with an integer score.

`PASS` means the retained declaration, attempts and selections reproduce the
proposition. `FAIL` means the selected bytes contradict it: a changed
commitment, a repeated problem or attempt identifier, an attempt for an
undeclared problem, more attempts than declared, a missing or repeated
selection, a selection for a problem without attempts, a selection that is not
the earliest best attempt, or a recorded score that differs from the
recomputed one. `UNKNOWN` means absent inputs, an empty problem declaration, a
declared problem with no retained attempt (its best-of-N choice is not
decidable), an unsupported metric, selection rule or tie break, an
`absolute-error` value outside the safe integers, or an exhausted selected
limit. Malformed or substituted requests, policies and certificates are
rejected before a computational verdict.

Relation to current `BENCH-1.2`, `BENCH-1.4`, `BENCH-3.6` and `BENCH-4.4`
(`CURRENT_BENCH_CHECKS.md`): those objectives retain exactly one run per
problem, execute a built-in oracle, compare an exact weighted solved fraction
with a selected minimum and, for `BENCH-4.4`, a reported score within a fixed
reporting tolerance. This objective admits several retained attempts per
problem, has no oracle execution, threshold, weight or aggregate, and is
neither a replacement for nor a restatement of those checks. No legacy verdict
is transferred in either direction.

Remaining `NOT_ESTABLISHED`: `BENCH-2.2` attempt inventory completeness
(attempts that were made but not retained are invisible here), `BENCH-2.3`
sequential adaptivity, `BENCH-2.4` contamination, `BENCH-2.5` response curve,
`BENCH-2.6` measurement feedback, candidate execution or answer authorship,
reference correctness, aggregate or ranked scores, whole BENCH dynamics tier
conformance, object-profile conformance, privacy, consent, governance and
security. The verifier and data operands are composed as namespace records
only; their truth is not checked. This check authorizes no scheduling,
spending or publication.

The certificate carries the retained declaration, attempts and selections. Do
not put confidential references or answers in a public certificate without
separate disclosure authority. Source or specification changes invalidate the
mechanism digest. Trust-root labels do not authenticate an observer. The
installed descriptor also binds `retained_selection.py`, the shared plain-value
request and policy capture helper; shared selection infrastructure does not
establish this proposition.
