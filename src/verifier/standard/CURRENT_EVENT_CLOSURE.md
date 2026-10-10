# Current EVENT-4.1: declared event-log closure over one selected head

Status: experimental, versioned current-object objective. Verifier Standard
(VSTD) specifies the claim; this Python mechanism is one reference checker.
JavaScript Object Notation (JSON) gives canonical retained bytes, and Secure
Hash Algorithm 256-bit (SHA-256) names commitments. Sequence numbers, event
counts and checking budgets are dimensionless. Evidence and certificate
limits are bytes.

The pair `verifier-current-object-obligations-1` / `EVENT-4.1` selects a
bounded **declared log closure** proposition over one selected head `EVENT`.
An independently selected exact `EVENT-3.1` request, policy and certificate
are retained and replayed against the installed child mechanism. The parent
request commits to each child selection, the exact child certificate bytes, a
selected `first_sequence` and a selected `log_digest`. The retained child
request must name the same head, head digest, collection digest and semantic
version, with coordinate `EVENT-3.1` and object kind `EVENT`. Only a child
`PASS` permits the closure clauses. A missing or `UNKNOWN` child remains
`UNKNOWN`; a failed or substituted child cannot establish closure.

Let E be the set of `EVENT` records in the child's retained finite
collection. Records of other kinds, such as the `TIME`, `SPACE` and meaning
operands, are not members of E. Three clauses are then checked:

1. **No orphan.** The identifiers in E equal the key set of the child's
   retained payload map, which `EVENT-3.1` already requires to equal the
   head's declared prerequisite cone. Every retained event is therefore the
   head or a transitive declared prerequisite of it.
2. **No gap or repeat.** The declared sequences over E, sorted, are exactly
   `first_sequence` through `first_sequence + |E| - 1`, each once.
3. **Log commitment.** The checker recomputes, from the child's retained
   records and never from a supplied log,
   `"sha256:" + canonical_digest({"schema_version":
   "verifier-current-event-closure-log-1", "head_id", "first_sequence",
   "events"})`, where `events` lists `{"object_id", "object_digest",
   "sequence"}` for each member of E in ascending sequence order. The result
   must equal the selected `log_digest`.

Because `EVENT-3.1` already requires every declared prerequisite to carry a
strictly lower sequence, a `PASS` also means the head carries the unique
maximum sequence and the numbering is a linear extension of the declared
prerequisite graph. That consequence is derived, not separately claimed.

The parent evidence is exactly `{schema_version, child_request,
child_policy, child_certificate}`, with the child certificate in canonical
base64. Parent ceilings are 100000 operations, 4096 items, 8 MiB of evidence
and a 16 MiB certificate. An event count above the selected item limit,
operations above the selected operation limit, evidence above the selected
evidence limit, absent evidence or an `UNKNOWN` child give `UNKNOWN`, except
that evidence above the 8 MiB ceiling is refused at build whatever limit is
selected. A certificate that retains such evidence and reproduces exactly
still gives `UNKNOWN` at recheck, since no selected limit exceeds the
ceiling. Canonical base64 decodes to at most three quarters of its length,
so a child retained within the ceiling is under 6 MiB, below the 8 MiB
`EVENT-3.1` certificate bound. A larger child is subsumed by the evidence
bound: it is refused at build and gives `UNKNOWN` at recheck. A limit key
outside the ceiling set, a limit outside one through its ceiling, a
`first_sequence` that is not a nonnegative safe integer, a malformed
commitment, mismatched evidence bytes, a certificate over the policy bound
and any substitution detected at recheck are refused before a verdict.

## Certificate obligations

One selected instance of this composition is two certificates, each under
its own obligation. The first is the `EVENT-4.1` parent certificate defined
here. The second is the exact `EVENT-3.1` child certificate that the parent
request selects and the parent evidence retains. The child is owned by its
`EVENT-3` obligation and stays a certificate of that objective: it is not
merely a checker call made on the parent's behalf, and it is not a duplicate
of the parent certificate. Replaying the child alone answers only the
`EVENT-3.1` proposition; replaying the parent checks the parent clauses and
the exact child relation. How many instances, event logs or certificates the
whole `EVENT-4.1` slot requires is `UNKNOWN`. One instance, including its
parent and child pair, does not fill the slot.

## Exclusions

`PASS` does **not** establish any of the following, which remain
`NOT_ESTABLISHED`:

- actual occurrence of any event, observer authenticity or physical
  causality; only the declared prerequisite edges are checked;
- completeness against events outside the selected collection; a truncated
  and renumbered collection can pass, and the only anchors are the external
  selections of `collection_digest`, `first_sequence` and `log_digest`, which
  are worthless when the selector is the adversary;
- logs with several heads or merged logs, which fail the no-orphan clause
  and are not supported;
- append-only behaviour or immutability over time;
- truth of the `TIME`, `SPACE` and meaning operands;
- the whole `EVENT` closure tier or object-profile conformance;
- privacy, consent, governance and security admission.

The parent certificate retains the exact child certificate, request and
policy as evidence, plus the parent request and replay result. Public release
of retained contents requires separate disclosure authority. Changed child
or parent source, selected specification, retained bytes or policy
invalidates the pinned mechanism. A digest or trust-root label is not proof
that any represented event occurred.
