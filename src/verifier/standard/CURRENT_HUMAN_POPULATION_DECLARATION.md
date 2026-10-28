# Current HUMAN-4.3: declared enrollment population

Status: experimental, versioned current-object objective. Verifier Standard
(VSTD) specifies the claim; this Python mechanism is one reference checker.
JavaScript Object Notation (JSON) gives canonical retained bytes, and Secure
Hash Algorithm 256-bit (SHA-256) names commitments. False-match and
false-non-match rates are dimensionless proportions in [0, 1]. Counts and
checking budgets are dimensionless.

## Selected row

The pair `verifier-current-object-obligations-1` / `HUMAN-4.3` selects a
bounded, strict subset of this `DOMAIN_OBLIGATIONS.md` requirement, quoted
verbatim:

> HUMAN-4.3 Population declaration: "Every assertion declares the exact enrollment population its uniqueness is relative to, and an undeclared population makes the uniqueness claim unestablished."

It also selects bounded subsets of its prerequisite rows:

> HUMAN-4.1 Evidence declaration: "Every humanness assertion declares the evidence class it rests on."

> HUMAN-4.2 Error-rate declaration: "Every assertion declares the error rates of that evidence class at the operating point actually used."

The verdict is decided from HUMAN-4.3 and these two listed dependencies only.
Two statics rows outside that dependency column are quoted for context. Neither
decides the verdict, and the result reports `human_3_2` and `human_3_5` as
`NOT_ESTABLISHED` in every verdict:

> HUMAN-3.2 Irreducible biometric error: "False-match and false-non-match rates are decision-theoretic facts of the operating point rather than implementation defects, and no operating point has both at zero."

> HUMAN-3.5 Relative uniqueness: "Uniqueness holds only relative to an enrollment population and a deduplication mechanism. No protocol establishes global uniqueness of a person, and an assertion claiming it is malformed."

## Proposition

The request selects one exact `HUMAN` namespace record and a complete finite
typed collection that must pass namespace composition. The humanness
assertions are the records typed `HUMAN`, read from the typed namespace record
and never from an identifier or label: a `BOT` whose identifier begins `human:`
is not an assertion, and a `HUMAN` whose identifier begins `bot:` is one.

Every assertion's payload must declare, and the verdict depends on nothing
else:

- `evidence_class` (HUMAN-4.1): one of the four HUMAN-1.2 classes
  (`biometric`, `hardware-attested`, `in-person`, `social-graph`) and one the
  installed policy admits. The policy's `admitted_evidence_classes` is a
  nonempty sorted unique subset of those four; anything else is rejected
  before replay.
- `operating_point` (HUMAN-4.2): a nonempty name for the operating point
  actually used.
- `false_match_rate` and `false_non_match_rate` (HUMAN-4.2): exact decimal
  strings of the form `0`, `1`, or either followed by a point and 1 to 64
  digits, decided as exact rationals. A JSON number, including a binary float,
  is `FAIL`. A rate above 1 is `FAIL`.
- `enrollment_population` (HUMAN-4.3): a nonempty name of the exact enrollment
  population. A population whose trimmed, case-folded text is `global`,
  `worldwide`, `all-humans` or `all humans` is not an exact enrollment
  population, so it is `FAIL` under HUMAN-4.3's own word "exact"; HUMAN-3.5
  corroborates that an assertion claiming global uniqueness is malformed.

An absent key and a `null` value are both undeclared.

Two retained observations are reported and never decide the verdict. Each is
the sorted list of assertion identifiers it holds for on `PASS`, and
`NOT_OBSERVED` otherwise:

- `deduplication_mechanism_declared` lists the assertions that declare a
  nonempty `deduplication_mechanism`; an undeclared mechanism does not decide
  the verdict, because HUMAN-3.5 is not in this row's dependency column.
- `both_rates_zero_declared` lists the assertions that declare both error
  rates zero; such an assertion does not decide the verdict, because HUMAN-3.2
  is not in this row's dependency column and HUMAN-4.2 asks only that the
  rates be declared at the operating point used.

## Verdicts

`PASS` means every typed `HUMAN` assertion in the selected collection makes
every required declaration above; `population_declaration` is then `PASS`.
`FAIL` names one assertion and the HUMAN-4.1, HUMAN-4.2 or HUMAN-4.3
declaration it lacks or breaks. Absent
evidence, or an exhausted operation, item or byte ceiling, is `UNKNOWN`. A
malformed request or policy raises `HumanPopulationDeclarationError` before
replay (`REJECTED`).

A `FAIL` refutes only the declaration proposition. It never decides
uniqueness. Under HUMAN-4.3 an undeclared population leaves the uniqueness
claim unestablished, so `uniqueness_claim` is `NOT_ESTABLISHED` in every
verdict, never `FAIL`.

## Closure

HUMAN-4.6 reads: "The assertion is closed only when evidence, error rates, population and accountability termination all hold; otherwise the result is UNKNOWN and never FAIL."

This certificate reports `closure_result` as `NOT_ESTABLISHED` in every
verdict. HUMAN-4.6 can never `PASS` here. Closure needs HUMAN-4.4
accountability termination in a natural person, which needs a HUMAN
certificate, and no adapter issues one. The certificates specified here decide
declared records only and are not such a certificate. `accountability_termination`
and `occupancy_termination` (HUMAN-4.4, HUMAN-4.5) are always `NOT_ESTABLISHED`.

## Exclusions

These certificates never establish that anyone is a person, or that a declared
evidence class, rate, operating point, population or mechanism is true.
Personhood, liveness, biometric accuracy, presentation and injection attack
resistance, uniqueness itself, death as a fact, authority, consent and privacy
are always `NOT_ESTABLISHED`. The whole HUMAN closure tier and object-profile
conformance remain `NOT_ESTABLISHED`.

## Invalidation

The certificate retains the exact evidence bytes, request and replay result.
Public release of retained contents requires separate disclosure authority.
Changed checker source, this specification, `NAMESPACE_OBJECTS.md`, retained
bytes or policy, including its admitted evidence classes, invalidates the
pinned mechanism. A digest or trust-root label is not proof that any assertion
is true.
