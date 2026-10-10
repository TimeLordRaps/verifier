# Current VERIFIER-3.1: run-bound checker observations of declared constraints

Status: experimental, versioned current-object objective. Verifier Standard
(VSTD) specifies the claim; this Python mechanism is one reference checker.
JavaScript Object Notation (JSON) gives canonical retained bytes, and Secure
Hash Algorithm 256-bit (SHA-256) names commitments. Event maxima count CPython
trace events and are dimensionless; report maxima are bytes; checking budgets
are dimensionless.

## Governing row

`DOMAIN_OBLIGATIONS.md`, VERIFIER-3.1 *Verifier substrate constraints*, verbatim:

> Execution-substrate identity, physical resource constraints and isolation require independent observations bound to the actual verifier run; caller declarations alone leave this profile UNKNOWN.

This objective mechanizes only the part of that row that a checker can decide
from inside one run: a declared constraint is matched by an observation that
the checker itself produced, bound to that run. The three named facets stay
`NOT_ESTABLISHED` in every result.

## Selection and run

The pair `verifier-current-object-obligations-1` / `VERIFIER-3.1` selects:

- one exact `VERIFIER` namespace record whose payload names the observed
  checker route: `checker_kind` `CURRENT_OBJECT_ROUTE`, plus the child
  semantic version, objective and represented kind, and the singleton typed
  collection containing it;
- one exact child request, policy and certificate for that registered route,
  each committed by digest in the parent request;
- a declarant label and one to thirty-two constraints, each a sorted unique
  `constraint_id`, a `quantity` and an integer `maximum` from 0 to 2^53 - 1.

The **run** is two in-process replays of the child certificate through the
registered route dispatcher, each under a counting `sys.settrace` tracer. Its
run digest commits the mechanism identifier, policy digest, subject, child
selection, limits and replay count. Constraints, declarant and evidence are
excluded so a declaration can cite the run it describes.

## Observations

The checker produces observations for exactly two quantities, with producer
`checker:verifier.current-verifier.run-bound-constraint-observations.1` and
the run digest:

- `traced_python_events`: trace events per replay. The tracer stops a replay
  as soon as the count exceeds min(declared maxima, `max_replay_events`). The
  relation is retained; the count is not, because finalizers and first-call
  effects make it process-dependent.
- `replay_report_bytes`: canonical byte length of the route report. Both
  replays must give identical canonical reports, so this value is retained.

Caller declarations (`declared_observations`) are retained, shape-checked and
counted, and are never admitted, whatever their producer label or run digest.
A declarant beginning with `checker:` is rejected.

## Verdicts

- `PASS`: both replays complete within the allowance, the reports are
  byte-identical, the child is reproduced with `PASS`, and every declared
  constraint is observed by the checker within its maximum.
- `FAIL`: an observed value exceeds its declared maximum (including an event
  overrun when the declared maximum is within the ceiling), the two reports
  differ, the route refuses the child, the child replays `FAIL`, or the
  retained subject or child bytes differ from the selection.
- `UNKNOWN`: a constraint names a quantity this checker does not observe,
  reason `CALLER_DECLARATION_ONLY` when only a caller record speaks to it and
  `NO_INDEPENDENT_OBSERVATION` otherwise; the event ceiling is spent before a
  larger declared maximum; the child is `UNKNOWN` or unavailable; evidence is
  missing; or the run is nested in another VERIFIER-3.1 run. An observed
  violation outranks an unobserved constraint.
- `REJECTED`: malformed request, policy or certificate, or a substituted
  selection, raises `VerifierRunConstraintsError`.

## Differences from VERIFIER-2.1

VERIFIER-2.1 asks whether the installed SIM checker reproduces independently
selected expected outcomes on finite cases; its subject is a checker's
answers. VERIFIER-3.1 asks whether declared limits on a run were observed by
the checker during that run; its subject is the run of a named route and the
provenance of each observation. It does not judge the child's outcomes beyond
requiring a reproduced `PASS`, and it applies to any registered route except
its own.

## Recursion

The child objective may not be `VERIFIER-3.1` or `VERIFIER-4.1`. A run that
starts while another VERIFIER-3.1 run is active on the same thread is
`UNKNOWN`. The route catalog is read when the request is captured, so an
unregistered child is rejected.

## Exclusions

Results always carry `execution_substrate_identity`,
`physical_resource_constraints`, `isolation`, `class_wide_soundness`,
`determinism_on_other_inputs`, `cross_process_or_platform_determinism`,
`general_termination`, `whole_verifier_statics` and
`object_profile_conformance` as `NOT_ESTABLISHED`. Trace events are not time,
memory, energy or instructions. Native code reached from Python is not
counted. Other threads are not traced. A digest or trust-root label is not
proof of which machine ran the replay. No authority, authenticity, privacy,
consent, security or safety conclusion follows.

## Invalidation

The policy pins this module, `current_object_routes.py`, the core
certificate, evidence, receipt and namespace modules, the shared selection
helpers, `NAMESPACE_OBJECTS.md` and this specification. A change to any of
them, including registering another route, makes the selected policy differ
from the installed mechanism. The child policy separately pins the child
mechanism. A certificate whose replay relation changes between build and
recheck does not reproduce and is rejected.
