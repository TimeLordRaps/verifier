# SimulacraBench synthetic closed-evaluation packet

This non-normative example maps one local, synthetic run of the pinned
SimulacraBench public evaluator into VSTD's availability, disclosure, and challenge
mechanisms. It is a concrete test of the case where verdict-critical bytes are available
to a declared evaluator but cannot be published to arbitrary reviewers.

## Bounded claim

The pinned phase-1 scorer evaluated the pinned marginal-counts baseline against a
committed 12,000-respondent **synthetic** sandbox in a local rehearsal with scoring seed
`20260822`. It returned `PASS` and the exact participant-visible reported skill `0.33`.

That sentence is about the participant-visible, privacy-processed output. The private
organizer log contains additional score detail and is deliberately not part of the public
packet.

## Private-data boundary statement

The aggregate result establishes only what the declared local synthetic evaluator
observed at the coordinate in `public_packet.json`. It does not establish a protected-data
run, hosted runner parity, a leaderboard entry, public score recomputation, organizer
review, or independent verification.

The public packet binds every verdict-critical artifact. Canonical upstream Git-blob
bytes, the exact submission archive, an LF-normalized public rendering of the generated
schema, and the aggregate result accompany the packet. The exact scored schema, hidden
synthetic respondent table, organizer log, and execution transcript have content
addresses, evaluator-only locators, and a retention commitment through
`2026-09-30T23:59:59Z`. Their derived level is `AVAILABLE`, not `PORTABLE`. If that
commitment is not renewed, the packet becomes stale; a digest alone cannot keep it
available.

## Verify the public view

From a VSTD source checkout:

```bash
PYTHONPATH=src python examples/simulacrabench_synthetic/verify_packet.py
PYTHONPATH=src python examples/simulacrabench_synthetic/verify_packet.py --json
```

The verifier performs no network access and receives no hidden records. It checks:

- canonical packet and challenge digests;
- byte identity of the bundled upstream snapshot and public artifacts;
- the declared availability floor and its limiting private artifacts;
- the explicit disclosure and trust boundaries;
- a non-disclosing challenge transition from `CHALLENGED` to `REVOKED` under the
  declared founder-operated evaluator.

The last transition demonstrates structural challenge handling. It is not an independent
challenge and does not create a VSTD-5 witness.

## Public and evaluator views

| View | Can inspect | Can conclude | Cannot conclude |
| :-- | :-- | :-- | :-- |
| Public | Pinned source bytes, exact submission ZIP, generated schema, commitments, participant-visible result, challenge record | The public packet is internally bound; private evidence is declared `AVAILABLE`; the synthetic challenge is structurally effective | The hidden-fixture score was publicly recomputed; private artifacts are portable; the evaluator is independent |
| Authorized evaluator | Everything in the public view plus the committed synthetic fixture, raw organizer log, and execution transcript | Whether the committed private bytes produce the declared participant-visible aggregate | Organizer endorsement, hosted parity, protected-data performance, or independent verification |

The deliberate mutant changes only the reported skill from `0.33` to `0.34`. Its public
filing makes that mutant claim `CHALLENGED`; the authorized aggregate-only transcript
revokes it without disclosing an individual record, item identifier, label, raw
prediction, or traceback. Other commitments are not revoked by that localized mismatch.

## What VSTD does not claim

VSTD is not accredited or a consensus standard, and this mapping does not claim
SimulacraBench adoption, endorsement, or independent implementation.

See [`CROSSWALK.md`](CROSSWALK.md) for the source-to-VSTD mapping and
[`UPSTREAM.md`](UPSTREAM.md) for exact provenance and licensing.
