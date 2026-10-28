# Current COLLECTIVE retained membership lifecycle

Verifier Standard (VSTD), JavaScript Object Notation (JSON), Secure Hash Algorithm
256-bit (SHA-256). Counts are dimensionless; byte bounds count encoded bytes.

Current `COLLECTIVE-2.1`, under `verifier-current-object-obligations-1`, replays one
externally selected finite ROLE admission/departure trace. It is distinct from
legacy finite collective decision assembly and from an actual quorum decision.
The [namespace](NAMESPACE_OBJECTS.md) defines COLLECTIVE membership as `roles: ROLE`.
Every endpoint must independently reproduce its selected
[COLLECTIVE-3.1 static certificate](CURRENT_COLLECTIVE_CONSTRAINTS.md).

The external lifecycle policy selects one declared clock, microsecond units and
the complete finite ordered event inventory. Every event has exactly `position`,
`event_id`, `time_us`, `action`, `role_id` and `role_digest`. Positions begin at
zero and are contiguous; identifiers are unique. Times are nonnegative integers
at most `2**53-1`, strictly increase and equal the next selected endpoint time.
These facts describe one selected clock declaration, not a physical clock,
historical event occurrence, independent observation or exhaustive live capture.

The request independently selects every endpoint's time, exact child certificate
byte commitment, child request and child policy. All children select the same
COLLECTIVE identifier; the terminal subject and complete collection match the
parent's external selection. Evidence retains the declared clock, exact selected
event inventory and ordered base64 child certificates. Each child's retained
evidence is rehashed and rechecked under its external selection. An embedded PASS
or an independently passing certificate for a different endpoint supplies nothing.

`ADMIT` adds a previously absent exact ROLE record to both the collection and
COLLECTIVE membership. `DEPART` removes an admitted exact ROLE record from both.
The ROLE digest must equal the external event selection. No other collection
identifier may appear or disappear. Every persistent record must stay identical;
the subject may change only its sorted roles operand and membership commitment,
which the checker recomputes from the resulting exact ROLE records. Charter,
quorum, constraint version and all other subject fields stay identical. Every
endpoint rechecks static quorum feasibility; the transition also recomputes it.
Charter/quorum updates and arbitrary ROLE changes are outside this mechanism.

Wrong chronology, retained event substitution, duplicate event identifiers,
impossible admissions/departures, changed persistent or unrelated records,
unselected child bytes, false static children and altered frozen fields produce
FAIL. Missing retained certificates or required inputs, an UNKNOWN static child,
unsupported lifecycle actions and exhausted selected bounds produce UNKNOWN.
Present contradictory events and available adjacent endpoint transitions are
checked before final absence reporting. A resource limit can stop inspection;
no unchecked contradiction is then claimed absent. Malformed external selections
and substituted parent certificates are refused.

Native ceilings are 64 events, 65 endpoint selections, 4096 items per structure,
1000000 parent operations, 16 mebibytes of evidence, 64 JSON nesting delimiters,
8 mebibytes per child certificate, and 32 mebibytes per parent certificate.
Input traversal, decoded child-certificate bytes, child-evidence traversal and
transition records consume the parent operation budget. Before each child
execution, its selected input/predicate and composition operation maxima are
reserved against two separate aggregate ceilings of 1000000 each. Each child
also enforces all its own externally selected static limits. These aggregate
ceilings can make a large otherwise well-shaped trace UNKNOWN. Smaller positive
selected limits bind at exact boundaries. Nesting is checked before recursion.

The mechanism digest binds the complete static mechanism digest, this module and
this specification. It therefore changes when shared readers, canonicalization,
namespace semantics or either contract/specification changes. Certificate recheck
reconstructs the whole envelope from retained evidence and external selection;
it cannot promote a substituted result.

All results preserve object-profile conformance, whole-tier conformance,
authority, actual execution, complete real event capture, physical timing and
an actual quorum decision as NOT_ESTABLISHED. No actor/human independence is
inferred. This objective does not close an applicable `.m` inventory or complete
any object's nine required tiers.

A native static child's typed unavailable checking capacity is accumulated as
missing endpoint support. Other available exact endpoints remain checked; a later
genuinely rechecked FAIL or independent present contradiction still refutes the
selected lifecycle. Unknown endpoint states cannot supply a transition PASS.
Semantic child reconstruction refusal remains a refutation, not unavailability.
