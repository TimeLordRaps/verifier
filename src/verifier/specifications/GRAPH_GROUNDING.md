# Verifier Standard (VSTD) Graph-axis grounded certification

**Status:** project specification for the additive Graph-axis certification contract.
**Certificate identifier:** `VSTD-GRAPH-GROUNDED-CERTIFICATION-1`.

## 1. Coordinates and meaning

`Graph-X.M` identifies obligation M within Graph numbered profile X. These are
dimensionless identifiers, not decimal numbers, software versions or confidence
scores. Each profile has its own finite sequence.

The Graph namespace is **disjoint** from the object namespace in
[`GROUNDED_CERTIFICATION.md`](GROUNDED_CERTIFICATION.md). `Graph-4.2` never aliases
`4.2`, neither catalogue admits the other's identifiers, and the two catalogue digests
are computed separately so that extending one cannot silently move the other.

Grounded certification on this axis requires the exact collection identifier,
deduplicated member set, recorded graph bytes, claim binding, obligation, evidence
bytes, mechanism implementation, trust roots and bounds to be bound and checked.
Certificates carry replay inputs and computed results. They MUST NOT accept a
declarant-supplied rating, collection profile or conformance grade as input.

The normative tables below decompose the existing Graph-profile requirements. They do
not replace the full requirements in `VSTD-Graph-1.md` through `VSTD-Graph-5.md`. A
mechanism MUST evaluate the stated obligation inside the exact declared collection
scope. Rating only the selected members, matching a digest or repeating a declared
rating does not discharge a substantive obligation about the collection's meaning.

## 2. Closure is the axis-defining condition

On the object axis an obligation ranges over one artifact. On this axis every
obligation ranges over the **reachable closure**: the deduplicated member set together
with every provenance ancestor and transformation hyperedge reachable from it. The
weakest reachable element caps the collection. A neighboring collection, topology or
claim contributes rating zero rather than partial support.

Profile zero is never established. A candidate computed from caller-supplied ratings
reports `NOT_ESTABLISHED`; only a path that reruns every member, ancestor and edge
rating proposition from embedded evidence through registered mechanisms may report
`MECHANISM_EVALUATED` and `ESTABLISHED`.

## 3. Graph-profile obligation catalogue

The reference catalogue is `verifier.core.profile_obligations.GRAPH_OBLIGATIONS`.
Every row below is individually evidence-bound. Dependencies listed here are within the
same numbered profile; cumulative profile prerequisites also apply.

### VSTD-Graph-1: Recorded Lineage

| Obligation | Name | Checked proposition | Dependencies | Source |
|---|---|---|---|---|
| Graph-1.1 | Collection coordinate | The collection identifier, deduplicated member set and exact recorded graph bytes are bound, and membership is explicit rather than inferred. | none | VSTD-Graph-1.md section 2 |
| Graph-1.2 | Recorded structure | Artifacts, transformation hyperedges and relation types parse under the declared vocabulary and the recorded relation is acyclic. | Graph-1.1 | VSTD-Graph-1.md section 2 |
| Graph-1.3 | Coverage recomputation | Every declared completeness dimension and the disclosed weighted summary are recomputed from the retained graph and are reported as coverage, never as a verdict, probability or trust score. | Graph-1.2 | VSTD-Graph-1.md section 3 |
| Graph-1.4 | Status admissibility | Every member and reachable ancestor carries an explicit status, and an omitted status remains unknown instead of becoming observed truth. | Graph-1.1 | VSTD-Graph-1.md section 4 |
| Graph-1.5 | Conflict retention | Incompatible retained evidence is kept as an explicit conflict record and is never averaged, collapsed or reduced to a scalar. | Graph-1.4 | VSTD-Graph-1.md section 4 |
| Graph-1.6 | Blast radius closure | Forward reachability from a revoked or challenged source is recomputed over the retained graph without mutating historical nodes. | Graph-1.2, Graph-1.4 | VSTD-Graph-1.md section 5 |

### VSTD-Graph-2: Bounded Collection Surface

| Obligation | Name | Checked proposition | Dependencies | Source |
|---|---|---|---|---|
| Graph-2.1 | Member rating re-execution | Every member rating is rerun from embedded evidence through a registered mechanism; a caller-supplied rating never admits the collection. | none | VSTD-Graph-2.md the evidence-bound path |
| Graph-2.2 | Ancestor reachability closure | Every provenance ancestor reachable from a member is enumerated and rated, because rating only the selected members is insufficient. | Graph-2.1 | VSTD-Graph-2.md the closure condition |
| Graph-2.3 | Edge rating re-execution | Every transformation hyperedge carries a rerun edge rating at this profile. | Graph-2.1 | VSTD-Graph-2.md the evidence-bound path |
| Graph-2.4 | Scope binding | Each rating proposition binds one digest over the exact graph bytes, deduplicated member set, collection identifier and claim binding, so a neighboring collection contributes rating zero. | Graph-2.1, Graph-2.2, Graph-2.3 | VSTD-Graph-2.md the rating proposition binding |
| Graph-2.5 | Bounded admission | The collection profile is recomputed with profile zero never established, and a refusal names the member, ancestor, status or edge obligation that prevented admission. | Graph-2.2, Graph-2.3, Graph-2.4 | VSTD-Graph-2.md the failure certificate |

### VSTD-Graph-3: Accountable Provenance Closure

| Obligation | Name | Checked proposition | Dependencies | Source |
|---|---|---|---|---|
| Graph-3.1 | Substrate rating re-execution | Every member and reachable ancestor rating at this profile is rerun over the exact evidence bytes through a registered mechanism. | none | VSTD-Graph-3.md the evidence-bound path |
| Graph-3.2 | Weakest reachable cap | The weakest reachable ancestor or transformation caps the collection, and rating only the selected members cannot lift that cap. | Graph-3.1 | VSTD-Graph-3.md the normative closure condition |
| Graph-3.3 | Out-of-closure contribution | Missing, failed, uncertain, neighboring and out-of-closure bindings contribute zero and prevent conformance rather than being skipped. | Graph-3.1 | VSTD-Graph-3.md the evidence-bound path |
| Graph-3.4 | Accountable actor binding | Trust roots, actor identity, delegation, rotation and revocation history are bound to the retained record and are not inferred from a name or a repeated observation. | Graph-3.1 | VSTD-Graph-3.md the accountability condition |
| Graph-3.5 | Accountable closure result | The accountable provenance result is recomputed from the preceding obligations with every blocker preserved. | Graph-3.2, Graph-3.3, Graph-3.4 | VSTD-Graph-3.md the closure condition |

### VSTD-Graph-4: Refutable Transformation Closure

| Obligation | Name | Checked proposition | Dependencies | Source |
|---|---|---|---|---|
| Graph-4.1 | Member refutability entry | Every member and reachable ancestor is evidence-bound at object profile 4, including all fourteen rungs; a candidate depth cannot enter this profile. | none | VSTD-Graph-4.md the profile condition |
| Graph-4.2 | Edge refutability closure | Every transformation hyperedge carries a refutability closure that the mechanism actually checks; naming one is insufficient. | Graph-4.1 | VSTD-Graph-4.md the edge rating condition |
| Graph-4.3 | Unevidenced edge rejection | Two refutable members connected by an unevidenced transformation do not compose into this profile. | Graph-4.2 | VSTD-Graph-4.md the composition condition |
| Graph-4.4 | Challenge localization | A challenge to the collection output localizes to a member, ancestor, transformation or the composition itself. | Graph-4.2 | VSTD-Graph-4.md the challenge condition |
| Graph-4.5 | Candidate ceiling explanation | An unsatisfiability certificate explains the candidate ceiling over caller-supplied ratings and does not establish conformance or validate a claimed closure record. | Graph-4.1 | VSTD-Graph-4.md the candidate path |
| Graph-4.6 | Offline replay | Proposition bindings and evidence bytes are embedded so every rating mechanism replays without the declarant. | Graph-4.2, Graph-4.3, Graph-4.4 | VSTD-Graph-4.md the evidence-bound path |

### VSTD-Graph-5: Corroborated Verification Network

| Obligation | Name | Checked proposition | Dependencies | Source |
|---|---|---|---|---|
| Graph-5.1 | Exact network entry | The collection is evidence-bound at the refutable transformation closure before any witness is admitted. | none | VSTD-Graph-5.md the profile condition |
| Graph-5.2 | Witness member rating | Registered mechanisms rerun the exact witness-corroborated member and ancestor ratings from embedded evidence. | Graph-5.1 | VSTD-Graph-5.md the evidence-bound path |
| Graph-5.3 | Witness transformation rating | Every transformation hyperedge carries a rerun witness-corroborated edge rating. | Graph-5.1 | VSTD-Graph-5.md the evidence-bound path |
| Graph-5.4 | Network scope binding | Every rating binds the exact graph bytes, deduplicated member set, collection identifier and claim binding across registries. | Graph-5.2, Graph-5.3 | VSTD-Graph-5.md the rating proposition binding |
| Graph-5.5 | Conflict inadmissibility | Conflicting witness records are retained and make the affected subject inadmissible; they are never averaged into a passing collection. | Graph-5.2 | VSTD-Graph-5.md the conflict condition |
| Graph-5.6 | Declared rating rejection | A result computed from self-declared ratings is not conformance at this profile, whatever its shape or count. | Graph-5.4 | VSTD-Graph-5.md the compatibility boundary |

## 4. Compatibility

The Graph request, policy and certificate identifiers are additive. Existing Graph
receipt identifiers, candidate-profile behaviour and historical receipts remain
unchanged. A legacy Graph receipt is evidence for a suitable mechanism, never
automatically a complete new certificate. Adding a Graph coordinate does not change the
object-axis catalogue digest, and no obligation on either axis is renumbered.
