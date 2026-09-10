## Coordinate

> **Acronyms:** identifier (ID); Secure Hash Algorithm 256-bit (SHA-256);
> Verifier Standard (VSTD).

- VSTD numbered profile or closure coordinate:
- Repository release or target commit:
- Claim, schema, or implementation seam:

## Change and evidence

- What changes:
- What does not change:
- Falsification condition:
- Tests added or updated:

## Promotion record

These fields are checked against the live pull request. Refresh them after every push.

- Final head commit: `FULL_COMMIT_ID`
- Final base commit: `FULL_COMMIT_ID`
- Executed integration commit: `FULL_COMMIT_ID`
- Repository-check event: `pull_request`
- Repository-check run: PENDING — numeric successful run ID whose coordinate artifact records the commits above.
- Promotion record SHA-256: PENDING — digest of the canonical promotion fields and complete human-gate section.
- Actionable findings: PENDING — replace with `CLEAR —` followed by every finding and its resolved disposition, or explain why none existed.
- Tests skipped or not run: PENDING — after the recorded repository-check run completes, copy its machine-produced values exactly as `DISCLOSED — test-evidence-sha256=<64hex> — total-skipped=<count>; skip-observation-omissions=<comma-separated-manifest-list>`, where `<64hex>` means exactly 64 lowercase hexadecimal characters; use `NONE — test-evidence-sha256=<64hex> — total-skipped=0; skip-observation-omissions=NONE` only when the bound manifest records zero skips and no observation omissions.
- Human acceptance evidence: PENDING — link an exact-head approving review or trusted maintainer comment containing `VSTD-HUMAN-ACCEPTANCE: FULL_COMMIT_ID PROMOTION_RECORD_SHA256`.
- Post-merge validation owner and surfaces: PENDING — replace with `ASSIGNED —` and name the owner plus the exact `main`, Pages, release, or other surfaces to observe.

## Human review gates

- [ ] Replace this template item with one line per proposition using `[ACCEPTED]` or `[NOT APPLICABLE]`, followed by the evidence-backed disposition. Green automation does not accept these gates.

## Consequences

- Serialized-format and compatibility impact:
- Trust roots, unknowns, residuals, and horizons:
- Downstream documents, schemas, examples, and receipts reviewed:

## Checklist

- [ ] I did not turn `UNKNOWN` or `CONFLICTED` into a clean result.
- [ ] I did not strengthen a claim without stronger evidence.
- [ ] I did not include secrets, private data, or proprietary operational material.
- [ ] Normative text, machine-readable surfaces, examples, and tests agree.
- [ ] README maturity, claims guidance, generated reference, and Pages status still agree.
- [ ] Every actionable review finding is resolved or explicitly retained as a blocker.
- [ ] The promotion record and human acceptance bind the current final head.
- [ ] Hosted and local evidence was refreshed after the final push.
- [ ] Every skipped or unrun check and its claim consequence is disclosed.
- [ ] Post-merge validation has a named owner; merge and release remain separately authorized actions.
