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
| The participant receives a privacy-processed aggregate and runtime; the organizer keeps raw detail | `README.md`, `score.py` | Saved participant-visible result is `SELF_CONTAINED`; raw log and synthetic fixture are access-controlled and only `IDENTIFIED` in the public packet | Public recomputation is `UNAVAILABLE`; a digest and retention promise are not retrieval evidence or proof of correctness |
| A score mismatch can be challenged without publishing respondent rows | VSTD profile construction over the public evaluator interface | `metric_recomputation_mismatch` moves the filed mutant to `CHALLENGED` | No adjudication or revocation follows without separately evidenced authorized checking |

## Exactness audit

| Question | Answer |
| :-- | :-- |
| Are the upstream files pinned to a full commit and bundled byte-for-byte? | Yes |
| Is the exact submitted ZIP bundled? | Yes |
| Is every input to the measured run synthetic? | Yes; the private fixture was produced only by the pinned synthetic generator, public toy schema, configuration, and a private high-entropy seed |
| Does the public packet demonstrate retrieval of every verdict-critical artifact? | No; it contains no retrieval observation and no private locator |
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
- The private artifacts remain `IDENTIFIED` unless an additive observation binds actual
  retrieved bytes to the declared artifact, locator, observer, and observation time.
- A filed `metric_recomputation_mismatch` leaves the targeted mutant `CHALLENGED` until a
  separate authorized adjudication is evidenced.
- The declared retention horizon does not elevate availability and is not silently
  rewritten into a retrieval claim.
