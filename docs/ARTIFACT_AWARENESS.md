# Artifact awareness and confidentiality of awareness

Verifier Standard (VSTD) v1.3.0 introduces these explicit interoperability terms,
prohibited inferences, and an experimental bounded composed-graph analyzer. This is not
a new receipt format, an awareness tracker, runtime mediation, or a general
confidentiality guarantee.

> Permission does not establish knowledge, and withholding direct access does not establish that something cannot be inferred.

## Meaning-bearing terms

- **Artifact awareness:** information an artifact has about another artifact, including
  its existence, contents, properties, dependencies, and awareness of other artifacts.
  A claim of awareness requires an exact artifact state and evidence of the named fact;
  a descriptive declaration alone does not establish that claim.
  Awareness of a claim is not verification of that claim.
- **Awareness relation:** a directed, context-specific relation from an aware artifact
  to the artifact and facts it is aware of. Knowing that an artifact exists is distinct
  from knowing its contents or its awareness relations. The relation itself can be
  confidential.
- **Awareness boundary:** an explicit separation between named facts that may be
  disclosed and facts whose disclosure or derivation is restricted. A declared boundary
  is policy, not evidence that the boundary is enforced.
- **Confidentiality of awareness:** constraints on exposing, acquiring, or propagating
  artifact awareness, including through intermediate artifacts and inference. Establishing
  that these constraints hold requires evidence for the named boundary and threat model.

These terms describe artifact-to-artifact relationships, not a new class of verifiers.
They do not depend on a particular application domain or on publisher identity.

## Three questions, recorded separately

| Question | Meaning | What does not establish it |
|---|---|---|
| Actual awareness | What information the exact artifact state has about another artifact; observations support only the facts their mechanism examines. | Permission, availability, a catalog entry, or an unexamined declaration. |
| Permitted awareness | What awareness a named policy and authority allow in a stated context. | Possession of information, successful proof checking, or a caller-supplied authorization label alone. |
| Potentially inferable awareness | What additional information can be derived from available observations under a named inference model and its assumptions. | Direct-access restrictions, omitted fields, an unsuccessful inference attempt, or absence of recorded awareness. |

These are separate dimensions, not interchangeable statuses or a progression toward
stronger assurance. An artifact may possess information it was not permitted to obtain.
Conversely, permission need not have been exercised. Failure to observe awareness leaves
it unknown; it does not demonstrate its absence.

## Composition and disclosure

**No automatic awareness inheritance:** if artifact A is aware of B, and B is aware of C,
neither A's awareness of C nor permission for A to acquire it follows automatically.
An actual disclosure or derivation needs its own relation, context and evidence.

Indirect inference nevertheless matters. In a non-critical inventory example, one
private artifact records a quantity, a public artifact records 3 items, and a combined
report discloses a total of 10 items. Given the explicit relation that the total is the
sum of those two quantities, subtraction reveals the private quantity: 7 items. Direct
access to the private artifact was unnecessary. The experimental analyzer can represent
this as a conjunctive knowledge hyperedge and return a concrete `FAIL` witness when every
premise and inference rule is supported by evidence.

Review metadata as well as payloads: artifact names, existence, dependency edges, receipts,
logs, output combinations and timing can reveal facts. A hash, signature, seal, omitted
payload or successful verification does not by itself establish confidentiality of
awareness. Any disclosure mechanism must name which facts may be revealed, to which
recipient, under which authority, and what inference and execution channels it covers.
Do not put confidential facts or confidential awareness relations into a public manifest
merely to describe a boundary that is supposed to protect them.

Fact and interface identifiers are caller-selected coordinates, not inherently opaque
tokens. Their spelling, presence and relationships can disclose protected information.
Contracts, witnesses and reports therefore require confidentiality handling appropriate
to the graph they describe; commitment-derived identifiers can reduce semantic leakage
but do not make the surrounding relationship metadata secret.

## v1.3.0 release boundary

The release defines this vocabulary and adds
`verifier.interoperability.untraversable`, an experimental analyzer for finite monotone
knowledge-hypergraph closure over an exact supplied composed graph. The contract binds one
observer, awareness mode, observation interval, query transcript and count, accessible
interfaces, capabilities, committed fact identities, protected facts, evidence-checked
inference rules, disclosure-channel coverage and resource bounds. It preserves `FAIL`,
`UNKNOWN`, `CONFLICTED` and `MATCH` as native results. A `FAIL` carries an all-premise
hyperpath witness; `MATCH` requires completed bounded closure and passing declared-model
completeness evidence.

Admission takes one strict snapshot of the supplied graph. Each interface binds exactly
the graph artifacts that source its exposed facts. A knowledge hyperedge tied to a graph
transformation must cover exactly that transformation's input and output artifact sets;
repeated use of one artifact in multiple input ports or multiple output ports is outside
the v1.3.0 supported subset. A self-transformation may still name the same artifact once
on each side; the input and output directions remain distinct in the graph digest and
witness.
Purely epistemic rules may omit a transformation identifier, but their evidence burden
remains explicit. Graph, observer, interface, rule and completeness evidence coordinates
are bound independently so evidence from a neighboring graph or awareness mode cannot be
silently replayed.

Every supported seed and rule binds the complete participating fact records, including
their commitments, disclosure channels and source artifacts. A concrete `FAIL` witness
retains whether each seed came from observer-state evidence or an interface disclosure,
the supporting evaluation digest, exact rule and transformation coordinates, and a
topological step order. Bounded rule firing uses the declared
`goal-distance-then-depth-then-hyperedge-id-v1` schedule so an immediately available
protected-fact path is considered before a same-depth intermediate path. Exhausting that
schedule still produces `UNKNOWN`, never `MATCH`.

The evidence-item and evidence-byte ceilings count the unique content-addressed evidence
bundle once. They do not bound repeated mechanism processing of those bytes; execution
time, memory and repeated-work controls remain separate prerequisites. The traversal
schedule is deterministic and goal-directed but is not a minimum-hyperpath solver, so a
small firing budget may conservatively return `UNKNOWN` even when a different schedule
could find a longer witness within that number of firings.

The analyzer does not establish real-world model completeness, universal
non-inferability, actual human knowledge, authorization, runtime mediation, actor identity,
intent, guilt, or confidentiality outside that exact coordinate. The analyzer does not implement a general inference engine:
only explicitly modeled and evidence-supported hyperedges fire.
Existing `READY` and integrity `PASS` results keep their original narrow meanings and do
not inherit an untraversability result. Unsupported semantics, missing mechanisms or
evidence, incomplete channel coverage, and exhausted bounds remain `UNKNOWN`.

Serialized structures, receipt identifiers and stored-package formats are unchanged.
Expanded diagnostic text changes earlier release-candidate report bytes and their digests.
Regenerate affected analyses, plans and readiness reports, and rebind declarations that
name their digests; do not reuse an earlier authorization binding for a changed plan.

Continuous awareness tracking, open-world inference discovery, runtime enforcement and
automatic downstream admission remain future work requiring separately specified
mechanisms, evidence and native-platform qualification. They are not supplied by this
bounded v1.3.0 analyzer.

Descriptive names remain primary. Bell-LaPadula's
[information-flow model](https://csrc.nist.gov/files/pubs/conference/1998/10/08/proceedings-of-the-21st-nissc-1998/final/docs/early-cs-papers/bell76.pdf)
and Giampaolo Bella's
[formal protocol work](https://link.springer.com/book/10.1007/978-3-540-68136-6)
are relevant influences, not names for VSTD's artifact-awareness semantics or claims that
their mechanisms have already been integrated.
