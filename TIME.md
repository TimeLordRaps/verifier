# TIME

Status: OPEN

TIME is the live repository-contradiction annunciator. Its status is repository process
metadata, not Verifier Standard (VSTD) receipt vocabulary. A live entry belongs here only
when current authoritative surfaces make incompatible claims about current semantics or
implementation. Runtime `CONFLICTED`, an honest `UNKNOWN`, roadmaps, ordinary work items,
limitations, and speculative research do not belong here.

For agent response rules, see [`AGENTS.md`](AGENTS.md). For human interpretation and
escalation, see [`HUMANS.md`](HUMANS.md).

## Live contradictions

### Independence terminology exceeds the implemented evidence binding

- **Controlling claim:** [`docs/CLAIMS_AND_LIMITS.md`](docs/CLAIMS_AND_LIMITS.md) limits
  “independently verified” to evidence binding distinct producer and checker actors plus
  the claimed implementation and execution seams; [`standard/VSTD-1.md`](standard/VSTD-1.md)
  states that version 1.2.0 has no adapter that can establish that condition.
- **Incompatible surfaces:** the zero-identity/zero-knowledge (ZIZK) experiment
  manifest/report, the experimental Supply Chain Integrity, Transparency, and Trust
  (SCITT) example/crosswalk, and VSTD-3 verification prose use “independent verification” for
  verifier-side recomputation, an offline verifier invocation, or separately maintained
  code without evidence of distinct actors.
- **Affected behavior:** a reader can mistake mechanism or implementation separation for
  the actor-independence claim that VSTD-1 reserves. Wire identifiers and historical
  receipt fields are unaffected; legacy code symbols must be explained rather than
  silently redefined.

### Generic receipt file paths are handled inconsistently

- **Controlling claim:** the common `vstd validate`, `vstd inspect`, and `vstd reproduce`
  commands accept a receipt coordinate, and the shared dispatcher recognizes either a
  receipt directory or an explicit receipt file.
- **Incompatible runtime:** validation and inspection read an explicitly supplied file,
  while `reproduce_run_receipt` discards its filename and searches the parent directory
  for `receipt.json`.
- **Affected behavior:** a valid renamed generic-run receipt validates and inspects but
  cannot reproduce. No wire or digest change is required.

When a contradiction is open, change the status to `Status: OPEN` and record the exact
coordinates, both incompatible claims, evidence for each side, and affected behavior. An
evidence-backed repair removes the resolved live entry and returns this file to
`Status: CLEAR`; Git history preserves the prior state. Development branches may remain
open. The tag-triggered publication workflow checks the exact tagged checkout and fails
unless this file contains exactly one `Status: CLEAR` line.
