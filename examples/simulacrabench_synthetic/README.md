# SimulacraBench synthetic closed-evaluation packet

> **Corrected specimen:** packet `VSTD-SB-SYNTH-002` supersedes the challenged
> `VSTD-SB-SYNTH-001` specimen. See [`CORRECTION.md`](CORRECTION.md).

This non-normative example maps one recorded local, synthetic run of the pinned
SimulacraBench public evaluator into VSTD's disclosure and challenge mechanisms. It
demonstrates what a public packet can honestly retain when verdict-critical private bytes
are not available to the public checker.

## Bounded recorded claim

Under one founder-operated trust root, the pinned phase-1 scorer was recorded as
evaluating the pinned marginal-counts baseline against a committed 12,000-respondent
**synthetic** sandbox with scoring seed `20260822`. The saved participant-visible output
is `PASS` with reported skill `0.33`.

The public package establishes the identity and internal binding of the public artifacts
and that saved aggregate. It does **not** rerun the score. It does not establish a
protected-data run, hosted runner parity, leaderboard entry, organizer review, or
independent verification.

## Availability result

The exact scored schema, hidden synthetic respondent table, organizer log, execution
transcript, and generator seed have content addresses and a declared retention horizon.
They have no public locator and no executed retrieval observation in this packet.
Therefore their derived level is `IDENTIFIED`, not `AVAILABLE`.

The bundle's public availability assessment is consequently:

```text
required: AVAILABLE
derived floor: IDENTIFIED
accepted: false
public score reproduction: UNAVAILABLE
```

A retention promise is not retrieval evidence. An authorized party could later publish
an additive retrieval observation, but that observation would remain scoped to its named
trust root and would not automatically become independent verification.

## Verify the public view

From a VSTD source checkout:

```bash
PYTHONPATH=src python examples/simulacrabench_synthetic/verify_packet.py
PYTHONPATH=src python examples/simulacrabench_synthetic/verify_packet.py --json
```

The verifier performs no network access and receives no hidden records. It checks:

- canonical packet and challenge digests;
- byte identity of the bundled upstream snapshot and public artifacts;
- the `IDENTIFIED` availability floor and its limiting private artifacts;
- the explicit disclosure, correction, and trust boundaries; and
- admission of a non-disclosing challenge, which ends at `CHALLENGED`.

It does not accept a private transcript, execute a retrieval, adjudicate the challenge,
or move the mutant claim to `REVOKED`.

## Public and private views

| View | Can inspect | Can conclude | Cannot conclude |
| :-- | :-- | :-- | :-- |
| Public | Pinned source bytes, exact submission ZIP, generated schema view, commitments, saved participant-visible result, challenge filing | The corrected packet is internally bound; the private artifacts are identified; the mutant filing is `CHALLENGED` | The hidden-fixture score was recomputed; private bytes are available; the challenge was adjudicated; the evaluator is independent |
| Private holder | Private bytes in addition to the public view | Only what a separately executed, recorded check actually observes under its declared trust root | Organizer endorsement, hosted parity, protected-data performance, public reproducibility, or independent verification |

The deliberate mutant changes only the saved reported skill from `0.33` to `0.34`. Filing
the declared mismatch challenge changes the mutant claim to `CHALLENGED`. No public
artifact in this package authorizes an adjudication, so the verifier stops there.

## What VSTD does not claim

VSTD is not accredited or a consensus standard, and this mapping does not claim
SimulacraBench adoption, endorsement, protected-data use, or independent implementation.

The general integration checklist is
[`docs/profiles/competition-evaluation.md`](../../docs/profiles/competition-evaluation.md),
and the bounded public wording is in
[`docs/CLAIMS_AND_LIMITS.md`](../../docs/CLAIMS_AND_LIMITS.md#claim-translation-table).

See [`CROSSWALK.md`](CROSSWALK.md) for the source-to-VSTD mapping and
[`UPSTREAM.md`](UPSTREAM.md) for exact provenance and licensing.
