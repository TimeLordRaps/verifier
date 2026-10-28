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

### Retained Tier-0 rerun selectors: gate selection repaired, closure-scanner agreement unverified

- Coordinates: `VSTD-T0.1` through `VSTD-T0.9`.
- Registered identity: `src/verifier/runtime/manifest_gate.py::_admission_identities`
  registers each retained slug identifier from the Tier-0 catalog as an obligation
  selector, and focused diagnostics emit those identifiers in `vstd gate` rerun
  commands.
- Original defect: `src/verifier/runtime/namespace_admission.py::assess_gate` only
  recognized the separate `<coordinate>-namespace-admission` selector, so every
  registered retained slug was refused as `NAMESPACE_GATE_SELECTION_INVALID` on the
  bounded admission fixture (all nine refused; all nine namespace-admission selectors
  selected).
- Repair state (2026-10-16, uncommitted working tree): `assess_gate` now resolves a
  registered retained slug to the row at the same coordinate. A namespace-only report
  never assessed the retained component, so it answers a retained selector `UNKNOWN`
  with `RETAINED_TIER_ZERO_COMPONENT_NOT_ASSESSED`, never `PASS`. Observed failing
  before the repair and passing after it in
  `tests/test_namespace_admission.py::test_every_retained_tier_zero_slug_is_a_selectable_focused_gate`
  (75 passed in that file).
- Still open: whether the closure scanner applies the same rule to both cumulative
  families is `UNKNOWN`; it has not been inspected. On the live root the printed
  rerun command now selects, but the focused gate's package admission returns `FAIL`
  (`TIER_ZERO_NODE_RECONCILER_DIGEST_DIFFERS`), so the command still reaches no
  verdict for a flagged object.
- Affected behavior: until the scanner is shown to share the selection rule, Polish 0
  cannot claim actionable diagnostics. Remove this entry when the scanner agrees and
  the live focused gate reaches a verdict.

### Namespace-only Tier-0 finalization does not establish the retained T0.5 denominator

- Coordinate: `VSTD-T0.5`.
- Normative proposition: `src/verifier/standard/TIER_ZERO.md` requires binding all
  234 installed kind-tier slots and all 408 installed route memberships; the
  extensible-namespace specification says the retained and namespace additions are
  cumulative, not alternatives.
- Namespace path: `src/verifier/runtime/namespace_admission.py::_finish` can mark the
  version-2 namespace profile `PASS`, `complete`, and `finalized` from namespace
  findings alone. That module contains no 234-slot or 408-route denominator check.
- Affected behavior: a standalone namespace-admission result can describe T0.5 as
  finalized without establishing the retained proposition named by the same
  coordinate. Polish 0 must conjoin the retained and namespace components, or the
  namespace-only result must use a narrower non-finalizing claim boundary.
- Partial boundary (2026-10-16, uncommitted): the focused gate no longer answers a
  retained selector `PASS` from a namespace-only report (see the entry above). `_finish`
  is unchanged, so the finalization claim above still stands.

### SIM-2.4 package route and source-native route name different mechanisms

- Coordinate: `SIM-2.4`.
- Package authority: `src/verifier/runtime/package_contract_profiles.py` and
  `src/verifier/runtime/manifest_gate.py` register the package obligation against
  `verifier.domains.contracts.sim_resource.recheck_sim_resource_certificate`, the
  signed-record mechanism whose own result keeps actual consumption `UNKNOWN`.
- Source-native authority: `src/verifier/runtime/self_polish_dynamics.py` selects
  `verifier.domains.contracts.sim_resource_fresh` for the same coordinate and states
  that historical signed records are not promoted.
- Documentation conflict: `src/verifier/standard/NAMESPACE_OBJECTS.md` says the
  coordinate is unregistered, while `src/verifier/standard/CURRENT_SIM_RESOURCE.md`
  and `src/verifier/standard/PACKAGE_POLISH.md` describe the registered signed route
  as distinct from the fresh-execution variant.
- Affected behavior: the same readable coordinate does not identify one unambiguous
  checking mechanism across package and source-native Polish. Root remigration and a
  package `SIM-2.4` conformance result remain blocked until the installed package route,
  obligation identifier, reasons, and documentation consistently select the reviewed
  fresh-execution/direct-provenance mechanism or name the signed auxiliary separately.

## Recording a contradiction

When a contradiction is open, change the status to `Status: OPEN` and record the exact
coordinates, both incompatible claims, evidence for each side, and affected behavior. An
evidence-backed repair removes the resolved live entry and returns this file to
`Status: CLEAR`; Git history preserves the prior state. Development branches may remain
open. The owner-dispatched publication workflow checks the exact tagged checkout and fails
unless this file contains exactly one `Status: CLEAR` line.
