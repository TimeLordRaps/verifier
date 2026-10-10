# Current HUMAN-2.5: declared biometric template irreversibility

Status: experimental, versioned current-object objective. Verifier Standard
(VSTD) specifies the claim; this Python mechanism is one reference checker.
JavaScript Object Notation (JSON) gives canonical retained bytes, and Secure
Hash Algorithm 256-bit (SHA-256) names commitments. Event positions are
dimensionless order indices. Counts and checking budgets are dimensionless.

## Selected row

The pair `verifier-current-object-obligations-1` / `HUMAN-2.5` selects a
bounded, strict subset of this `DOMAIN_OBLIGATIONS.md` requirement, quoted
verbatim:

> HUMAN-2.5 Template irreversibility: "A compromised biometric template does not rotate: revocation withdraws the binding and never restores the secrecy of the trait, so a breach is declared as permanent rather than as remediated."

It also selects bounded subsets of its prerequisite row HUMAN-2.4 and of that
row's own prerequisite HUMAN-2.1:

> HUMAN-2.1 Enrollment: "Enrollment into the humanness assertion is declared as an event with its evidence class and its instrument."

> HUMAN-2.4 Revocation on compromise: "Revocation on compromise withdraws the assertion from the position in the order at which it takes effect."

## Proposition

The request selects one exact `HUMAN` namespace record, a complete finite typed
collection and the SHA-256 commitment of one retained, declared event log. The
subject's kind is read from its typed namespace record, never from an
identifier or label: a `BOT` or `AGENT` whose identifier begins `human:` is not
a `HUMAN` subject. The collection must pass namespace composition first.

The log is an ordered array of declared events. Positions are integers that
strictly increase. The admitted vocabulary is closed:

- `enrollment` declares `template_id`, `evidence_class` and `instrument`. The
  evidence class must be declared, must be one of the HUMAN-1.2 classes, and in
  a template log must be `biometric`. The instrument must be a nonempty name. A
  template is enrolled once, before any other event names it.
- `reverification` names an enrolled template.
- `compromise` names an enrolled template and declares `breach`, which must be
  `permanent`. A breach declared `remediated`, or anything else, is `FAIL`.
- `revocation` must follow a declared compromise of its template, occurs at most
  once per template, and declares an `effective_position` no earlier than its
  own position. A retroactive effective position is `FAIL`. This is the reading
  of "the position in the order at which it takes effect": the withdrawal is
  anchored at or after the revocation in the declared order, never before it.
- `rotation`, `restoration`, `rebinding` and `remediation` are the row's own
  words for what a breached template never undergoes. They are admitted only
  so that their presence is `FAIL`.

After a template's declared breach, no later event other than its single
revocation may name that template. A re-verification of it, a second
enrollment of it, or a second compromise of it is `FAIL`. A later enrollment
must therefore use a distinct template. Any other event kind is outside the
selected vocabulary and is `FAIL`; death (HUMAN-2.6) is not in it.

## Verdicts

`PASS` means the selected retained declared log satisfies every condition
above; `template_irreversibility` is then `PASS`. `FAIL` names one
counterexample event. A missing log, an exhausted operation, item or byte
ceiling, or absent evidence is `UNKNOWN`. A malformed request or policy raises
`HumanTemplateIrreversibilityError` before replay (`REJECTED`).

## Exclusions

These certificates decide properties of declared records only. They never
establish that anyone is a person, that a template was captured, breached or
revoked in the world, that a declared breach was real, or that the declared
order matches wall-clock order. Personhood, liveness, biometric accuracy,
presentation and injection attack resistance, uniqueness, death as a fact,
authority, consent and privacy are always `NOT_ESTABLISHED`. Re-verification
semantics (HUMAN-2.2), evidence aging (HUMAN-2.3), the whole HUMAN dynamics
tier and object-profile conformance remain `NOT_ESTABLISHED`.

## Invalidation

The certificate retains the exact evidence bytes, request and replay result.
Public release of retained contents requires separate disclosure authority.
Changed checker source, this specification, `NAMESPACE_OBJECTS.md`, retained
bytes or policy invalidates the pinned mechanism. A digest or trust-root label
is not proof that any event occurred.
