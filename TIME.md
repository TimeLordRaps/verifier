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

### TIME-2026-08-26-001 — Version 1.2.0 is presented as released before it exists

- [`CITATION.cff:2,7-8`](CITATION.cff) tells readers to cite “this release,” names
  version 1.2.0, and dates it 2026-08-24. [`CHANGELOG.md:12`](CHANGELOG.md) instead
  dates 1.2.0 to 2026-08-25. [`README.md:182`](README.md) instructs installation of
  `verifier-standard==1.2.0`.
- Observed on 2026-08-26: GitHub's latest public release is `v1.1.3`, no `v1.2.0`
  tag exists, and the Python Package Index exposes only `verifier-standard==1.1.3`.
- A newcomer following the installation or citation surface receives a nonexistent
  package/release, and the two repository release dates cannot both identify the same
  event. Do not treat 1.2.0 as released or assign its release date until publication has
  actually completed.

### TIME-2026-08-26-002 — VSTD-4 depth accepts declarations as established evidence

- [`standard/VSTD-4.md:11,30-32,54-55`](standard/VSTD-4.md) calls VSTD-4 an
  implemented project specification and requires VSTD-1, VSTD-2, VSTD-3, each rung's
  evidence, and every lower-layer precondition before VSTD-4 conformance.
- [`src/verifier/core/depth.py:294-318`](src/verifier/core/depth.py) treats any nonempty
  string at each rung identifier as asserted evidence. The public receipt schema likewise
  defines an evidence reference as only a nonempty string at
  [`receipts/schema/vstd4_receipt.json:46-47`](receipts/schema/vstd4_receipt.json), and
  neither surface accepts or validates lower-layer receipts.
- Falsification on 2026-08-26: fourteen copies of `arbitrary-nonempty-text`, with
  non-content-addressed policy and evidence roots and no VSTD-1/2/3 inputs, produced depth
  14; `require_vstd5_entry` accepted it. The certificate checks the generated Boolean
  formula, not whether the named artifacts establish the rungs.
- Consequently, current depth 14 and the implemented VSTD-5 entry gate exceed the
  normative evidence established by the runtime. They must not be presented as VSTD-4
  conformance or readiness until evidence binding and lower-layer preconditions are checked
  or the output is explicitly bounded as non-conformant candidate computation.

### TIME-2026-08-26-003 — Public Graph maturity labels erase `NOT_ESTABLISHED`

- The first-view architecture image labels Graph layers 2, 3, and 4 `IMPLEMENTED` at
  [`docs/assets/vstd-overview.svg:71-73`](docs/assets/vstd-overview.svg), and the Supply
  Chain Integrity, Transparency, and Trust (SCITT) crosswalk says VSTD-Graph has
  “implemented graph levels and policy checks” at
  [`docs/standards/VSTD_SCITT_CROSSWALK.md:108`](docs/standards/VSTD_SCITT_CROSSWALK.md).
- The normative layer statuses instead say only candidate computation is implemented and
  rating-to-evidence binding is not implemented at
  [`standard/VSTD-Graph-2.md:6,15`](standard/VSTD-Graph-2.md),
  [`standard/VSTD-Graph-3.md:6,19`](standard/VSTD-Graph-3.md), and
  [`standard/VSTD-Graph-4.md:8`](standard/VSTD-Graph-4.md). The receipt schema requires
  `conformance_status = NOT_ESTABLISHED` at
  [`receipts/schema/vstd_graph_receipt.json:169`](receipts/schema/vstd_graph_receipt.json).
- The public labels therefore collapse implemented candidate calculation into implemented
  layer conformance. Public status surfaces must retain the candidate and
  `NOT_ESTABLISHED` qualifiers.

### TIME-2026-08-26-004 — The SCITT crosswalk claims an unimplemented challenge-to-Graph seam

- [`docs/standards/VSTD_SCITT_CROSSWALK.md:110`](docs/standards/VSTD_SCITT_CROSSWALK.md)
  says VSTD challenge state can revoke artifacts and Graph level degrades on revoked
  ancestors.
- [`docs/ARCHITECTURE.md:186,190-195`](docs/ARCHITECTURE.md) says the challenge ledger
  changes claim status but no adapter binds that status into a Graph artifact; automatic
  cross-surface propagation is `NOT_ESTABLISHED`. The reference Graph query only discovers
  a blast radius and does not mutate historical nodes
  ([`standard/VSTD-Graph-1.md:131-138`](standard/VSTD-Graph-1.md)).
- Graph candidate calculation does degrade after an artifact node already records an
  inadmissible status; the challenge ledger does not cause that state transition. Until a
  binding mechanism exists, the crosswalk must not present the two implemented components
  as an implemented revocation path.

When a contradiction is open, change the status to `Status: OPEN` and record the exact
coordinates, both incompatible claims, evidence for each side, and affected behavior. An
evidence-backed repair removes the resolved live entry and returns this file to
`Status: CLEAR`; Git history preserves the prior state. Development branches may remain
open, but a release candidate requires maintainer confirmation that TIME is clear.
