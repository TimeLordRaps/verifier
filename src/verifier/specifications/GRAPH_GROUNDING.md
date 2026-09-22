# Verifier Standard (VSTD) Graph-axis grounded certification

**Status:** project specification for the additive Graph-axis certification contract.
**Certificate identifier:** `verifier-graph-grounded-certification-1`.

## 1. Coordinates and meaning

`GRAPH-X.M` identifies obligation M within Graph numbered profile X. These are
dimensionless identifiers, not decimal numbers, software versions or confidence
scores. Each profile has its own finite sequence.

The Graph namespace is **disjoint** from the object namespace in
[`GROUNDED_CERTIFICATION.md`](GROUNDED_CERTIFICATION.md). `GRAPH-4.2` never aliases
`4.2`, neither catalogue admits the other's identifiers, and the two catalogue digests
are computed separately so that extending one cannot silently move the other.

Grounded certification on this axis requires the exact collection identifier,
deduplicated member set, recorded graph bytes, claim binding, obligation, evidence
bytes, mechanism implementation, trust roots and bounds to be bound and checked.
Certificates carry replay inputs and computed results. They MUST NOT accept a
declarant-supplied rating, collection profile or conformance grade as input.

The normative tables below decompose the existing Graph-profile requirements. They do
not replace the full requirements in `GRAPH-1.md` through `GRAPH-5.md`. A
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

### GRAPH-1: Recorded Lineage

| Obligation | Name | Checked proposition | Dependencies | Source |
|---|---|---|---|---|
| GRAPH-1.1 | Collection coordinate | The collection identifier, deduplicated member set and exact recorded graph bytes are bound, and membership is explicit rather than inferred. | none | GRAPH-1.md section 2 |
| GRAPH-1.2 | Recorded structure | Artifacts, transformation hyperedges and relation types parse under the declared vocabulary and the recorded relation is acyclic. | GRAPH-1.1 | GRAPH-1.md section 2 |
| GRAPH-1.3 | Coverage recomputation | Every declared completeness dimension and the disclosed weighted summary are recomputed from the retained graph and are reported as coverage, never as a verdict, probability or trust score. | GRAPH-1.2 | GRAPH-1.md section 3 |
| GRAPH-1.4 | Status admissibility | Every member and reachable ancestor carries an explicit status, and an omitted status remains unknown instead of becoming observed truth. | GRAPH-1.1 | GRAPH-1.md section 4 |
| GRAPH-1.5 | Conflict retention | Incompatible retained evidence is kept as an explicit conflict record and is never averaged, collapsed or reduced to a scalar. | GRAPH-1.4 | GRAPH-1.md section 4 |
| GRAPH-1.6 | Blast radius closure | Forward reachability from a revoked or challenged source is recomputed over the retained graph without mutating historical nodes. | GRAPH-1.2, GRAPH-1.4 | GRAPH-1.md section 5 |

### GRAPH-2: Bounded Collection Surface

| Obligation | Name | Checked proposition | Dependencies | Source |
|---|---|---|---|---|
| GRAPH-2.1 | Member rating re-execution | Every member rating is rerun from embedded evidence through a registered mechanism; a caller-supplied rating never admits the collection. | none | GRAPH-2.md the evidence-bound path |
| GRAPH-2.2 | Ancestor reachability closure | Every provenance ancestor reachable from a member is enumerated and rated, because rating only the selected members is insufficient. | GRAPH-2.1 | GRAPH-2.md the closure condition |
| GRAPH-2.3 | Edge rating re-execution | Every transformation hyperedge carries a rerun edge rating at this profile. | GRAPH-2.1 | GRAPH-2.md the evidence-bound path |
| GRAPH-2.4 | Scope binding | Each rating proposition binds one digest over the exact graph bytes, deduplicated member set, collection identifier and claim binding, so a neighboring collection contributes rating zero. | GRAPH-2.1, GRAPH-2.2, GRAPH-2.3 | GRAPH-2.md the rating proposition binding |
| GRAPH-2.5 | Bounded admission | The collection profile is recomputed with profile zero never established, and a refusal names the member, ancestor, status or edge obligation that prevented admission. | GRAPH-2.2, GRAPH-2.3, GRAPH-2.4 | GRAPH-2.md the failure certificate |

### GRAPH-3: Accountable Provenance Closure

| Obligation | Name | Checked proposition | Dependencies | Source |
|---|---|---|---|---|
| GRAPH-3.1 | Substrate rating re-execution | Every member and reachable ancestor rating at this profile is rerun over the exact evidence bytes through a registered mechanism. | none | GRAPH-3.md the evidence-bound path |
| GRAPH-3.2 | Weakest reachable cap | The weakest reachable ancestor or transformation caps the collection, and rating only the selected members cannot lift that cap. | GRAPH-3.1 | GRAPH-3.md the normative closure condition |
| GRAPH-3.3 | Out-of-closure contribution | Missing, failed, uncertain, neighboring and out-of-closure bindings contribute zero and prevent conformance rather than being skipped. | GRAPH-3.1 | GRAPH-3.md the evidence-bound path |
| GRAPH-3.4 | Accountable actor binding | Trust roots, actor identity, delegation, rotation and revocation history are bound to the retained record and are not inferred from a name or a repeated observation. | GRAPH-3.1 | GRAPH-3.md the accountability condition |
| GRAPH-3.5 | Accountable closure result | The accountable provenance result is recomputed from the preceding obligations with every blocker preserved. | GRAPH-3.2, GRAPH-3.3, GRAPH-3.4 | GRAPH-3.md the closure condition |

### GRAPH-4: Refutable Transformation Closure

| Obligation | Name | Checked proposition | Dependencies | Source |
|---|---|---|---|---|
| GRAPH-4.1 | Member refutability entry | Every member and reachable ancestor is evidence-bound at object profile 4, including all fourteen rungs; a candidate depth cannot enter this profile. | none | GRAPH-4.md the profile condition |
| GRAPH-4.2 | Edge refutability closure | Every transformation hyperedge carries a refutability closure that the mechanism actually checks; naming one is insufficient. | GRAPH-4.1 | GRAPH-4.md the edge rating condition |
| GRAPH-4.3 | Unevidenced edge rejection | Two refutable members connected by an unevidenced transformation do not compose into this profile. | GRAPH-4.2 | GRAPH-4.md the composition condition |
| GRAPH-4.4 | Challenge localization | A challenge to the collection output localizes to a member, ancestor, transformation or the composition itself. | GRAPH-4.2 | GRAPH-4.md the challenge condition |
| GRAPH-4.5 | Candidate ceiling explanation | An unsatisfiability certificate explains the candidate ceiling over caller-supplied ratings and does not establish conformance or validate a claimed closure record. | GRAPH-4.1 | GRAPH-4.md the candidate path |
| GRAPH-4.6 | Offline replay | Proposition bindings and evidence bytes are embedded so every rating mechanism replays without the declarant. | GRAPH-4.2, GRAPH-4.3, GRAPH-4.4 | GRAPH-4.md the evidence-bound path |

### GRAPH-5: Corroborated Verification Network

| Obligation | Name | Checked proposition | Dependencies | Source |
|---|---|---|---|---|
| GRAPH-5.1 | Exact network entry | The collection is evidence-bound at the refutable transformation closure before any witness is admitted. | none | GRAPH-5.md the profile condition |
| GRAPH-5.2 | Witness member rating | Registered mechanisms rerun the exact witness-corroborated member and ancestor ratings from embedded evidence. | GRAPH-5.1 | GRAPH-5.md the evidence-bound path |
| GRAPH-5.3 | Witness transformation rating | Every transformation hyperedge carries a rerun witness-corroborated edge rating. | GRAPH-5.1 | GRAPH-5.md the evidence-bound path |
| GRAPH-5.4 | Network scope binding | Every rating binds the exact graph bytes, deduplicated member set, collection identifier and claim binding across registries. | GRAPH-5.2, GRAPH-5.3 | GRAPH-5.md the rating proposition binding |
| GRAPH-5.5 | Conflict inadmissibility | Conflicting witness records are retained and make the affected subject inadmissible; they are never averaged into a passing collection. | GRAPH-5.2 | GRAPH-5.md the conflict condition |
| GRAPH-5.6 | Declared rating rejection | A result computed from self-declared ratings is not conformance at this profile, whatever its shape or count. | GRAPH-5.4 | GRAPH-5.md the compatibility boundary |

## 4. Compatibility

The Graph request, policy and certificate identifiers are additive. Existing Graph
receipt identifiers, candidate-profile behaviour and historical receipts remain
unchanged. A legacy Graph receipt is evidence for a suitable mechanism, never
automatically a complete new certificate. Adding a Graph coordinate does not change the
object-axis catalogue digest, and no obligation on either axis is renumbered.
