# Current HYPER-2.3: UNKNOWN absorption over selected direct operands

Status: experimental, versioned current-object objective. Verifier Standard
(VSTD) specifies the claim; this Python mechanism is one reference checker.
JavaScript Object Notation (JSON) gives canonical retained bytes, and Secure
Hash Algorithm 256-bit (SHA-256) names commitments. Byte limits are bytes.
Meta-tiers, counts and checking budgets are dimensionless.

## Row

The pair `verifier-current-object-obligations-1` / `HYPER-2.3` decides a
bounded strict subset of this row of `DOMAIN_OBLIGATIONS.md` (line 611):

> | HYPER-2.3 | UNKNOWN absorption | One UNKNOWN operand makes the composition UNKNOWN. | HYPER-2.2 | none |

`META_TIERS.md` lines 389-391 state the same rule in prose, and lines
1007-1016 take the gate "Operands non-`UNKNOWN`" from it.

## Proposition

For one exact HYPER record in an exact retained typed collection, each
selected child certificate is bound to one distinct direct operand record and
replayed through the registered current-object route. A direct operand with
no selected child, or whose child replays `UNKNOWN` or is unavailable, is
`UNKNOWN`, and one `UNKNOWN` direct operand makes the composed verdict
`UNKNOWN`. Otherwise any `FAIL` operand makes it `FAIL`, and all `PASS`
operands make it `PASS`. The certificate's `status` is that composed verdict.

## Mechanism

The request commits to the HYPER subject, its record digest, the collection
commitment and a sorted list of child selections. Each selection names one
target, one current coordinate and the digests of the exact child request,
policy and certificate bytes. At most one selection per target is admitted.
The checker, in order:

1. reconstructs every retained namespace record, requires identifier order
   and runs `assess_composition` against the selected collection commitment.
   That applies the HYPER rule "relational composition requires named
   nonempty operands" (`core/namespace.py` line 302), unbound-reference
   refusal (line 261) and cycle refusal (line 276);
2. requires the root to be the selected HYPER record with the exact digest;
   `NAMESPACE_OBJECTS.md` lines 100-101 admit named, nonempty relational
   operands of any kind;
3. before any replay, binds every retained child to its selection by digest
   and requires the child request's `semantic_version`, `coordinate`,
   `subject_id` and `object_digest` to name exactly that direct operand
   record. A selection naming a record that is not a direct operand, a stale
   operand digest, a substituted child, or a wrong subject is `FAIL`;
4. replays each child through `current_object_routes`, with the operand's
   own kind as the represented kind. A route refusal is `FAIL`; an
   unavailable route or a non-reproduced replay makes that operand `UNKNOWN`;
5. folds the per-operand verdicts by the row, as in the proposition.

Records in the collection that are not direct operands, and that no
selection names, do not change the verdict.

## Difference from HYPER-4.1

`HYPER-4.1` (`CURRENT_HYPER_CLOSURE.md`, `hyper_closure.py`) decides that the
retained records are exactly the transitive operand cone. It replays no
operand certificate, and an unrelated record makes it `FAIL`. `HYPER-2.3`
replays the selected certificates of direct operands and composes their
verdicts. It ignores unrelated, unselected records, and it decides nothing
about transitive closure. A cone that passes `HYPER-4.1` with no selected
children is `UNKNOWN` here.

## Seam with existing negative precedence

Existing composed checks give `FAIL` precedence over gaps: see
`child_selection.py` line 50 and `certificate_dag.py` lines 437-439. For the
mixed case of one `FAIL` and one `UNKNOWN` operand, this objective follows the
row and returns `UNKNOWN`. The difference is deliberate and scoped to
`HYPER-2.3`. It does not change those modules.

## Exclusions

This objective does not define a total order on operand strengths
(`HYPER-2.1`) or decide strength non-increase (`HYPER-2.2`, the row's listed
dependency). It does not decide recomposition, associativity or depth
propagation (`HYPER-2.4` to `HYPER-2.6`), saturation or closure (`HYPER-4`),
the whole HYPER dynamics tier, or object-profile conformance. All of these
stay `NOT_ESTABLISHED` in the result. It makes no authority, privacy, consent,
governance, security or payload-truth claim. A child `PASS` means only what
that child's own objective means.

## Invalidation

A change to the selected HYPER record, collection, child selections, retained
child bytes, policy, limits, this module, `current_object_routes.py`,
`NAMESPACE_OBJECTS.md`, `DOMAIN_OBLIGATIONS.md` or this specification
invalidates the pinned mechanism. Release of the retained children requires
separate disclosure authority.
