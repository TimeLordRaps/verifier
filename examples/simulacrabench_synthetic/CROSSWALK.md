# SimulacraBench-to-VSTD crosswalk

This crosswalk is pinned to the upstream commit recorded in [`UPSTREAM.md`](UPSTREAM.md).
It maps observable public evaluator mechanics; it does not infer hidden infrastructure or
organizer intent.

| SimulacraBench public mechanic | Pinned evidence | VSTD representation in this example | Preserved limitation |
| :-- | :-- | :-- | :-- |
| A submission ZIP supplies `main.py`, optional `requirements.txt`, and `predict(frame, schema)` | `README.md`, `tools/check_submission_zip.py`, baseline files | Exact ZIP and source bytes are `SELF_CONTAINED` and content-addressed | Passing the ZIP checker does not establish a successful evaluation |
| Dependencies are installed before the scored run | `score.py`, `config.yml` | Dependency declaration is committed separately from the run transcript | This local rehearsal did not reproduce the hosted image or hardware |
| Runtime sockets are disabled before submission import | `score.py` | `network_control` is a claim-coordinate parameter and an admissible execution-receipt challenge target | The observed control was in-process socket denial, not container-level isolation |
| Phase 1 exposes TRAIN and scores DEV under a 900-second prediction budget | `README.md`, `config.yml`, `score.py` | Phase, data view, timeout, source commit, and scoring seed are bounded execution fields | No protected TEST data or hosted API path was exercised |
| The participant receives a privacy-processed aggregate and runtime; the organizer keeps raw detail | `README.md`, `score.py` | Participant-visible result is `SELF_CONTAINED`; raw log and synthetic fixture are access-controlled `AVAILABLE` artifacts | Public recomputation is `UNAVAILABLE`; a hash is not disclosure or proof of correctness |
| A score mismatch can be assessed without publishing respondent rows | VSTD profile construction over the public evaluator interface | `metric_recomputation_mismatch` moves a filed mutant to `CHALLENGED`, then an authorized aggregate-only adjudication moves it to `REVOKED` | Founder-operated adjudication is not independent and not VSTD-5 |

## Exactness audit

| Question | Answer |
| :-- | :-- |
| Are the upstream files pinned to a full commit and bundled byte-for-byte? | Yes |
| Is the exact submitted ZIP bundled? | Yes |
| Is every input to the measured run synthetic? | Yes; the private fixture was produced only by the pinned synthetic generator, public toy schema, configuration, and a private high-entropy seed |
| Can the declared evaluator retrieve every verdict-critical artifact through the retention horizon? | Yes, by the declared evaluator-only locator |
| Can an arbitrary public reviewer retrieve the hidden fixture and raw log? | No |
| Can the public verifier recompute the score? | No |
| Was the fixture commitment externally timestamped before execution? | No |
| Was hosted H100, CPU, memory, container, API, or leaderboard parity established? | No |
| Was protected SimulacraBench data used? | No |
| Has an organizer reviewed, adopted, or endorsed this mapping? | No |
| Is the synthetic evaluator independent or a VSTD-5 witness? | No |
| Does this example claim aggregate VSTD-4 depth? | No |

## Failure semantics

- A bundled-byte mismatch rejects the packet.
- Loss of a private artifact before the retention horizon is an
  `availability_failure`; the affected claim must degrade.
- A different participant-visible aggregate under the bound inputs is a
  `metric_recomputation_mismatch`; the affected result claim is revoked after authorized
  adjudication.
- After `2026-09-30T23:59:59Z`, the availability assertion is stale unless an additive
  renewal record extends it. The existing packet is not silently rewritten.
