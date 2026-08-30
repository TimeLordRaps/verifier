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

### GUILT composition can exceed separately earned components

- **Implementation coordinate:**
  `src/verifier/data/assurance.py::AssuranceLedger.diagnose`
- **Current implementation proposition:** one combined
  `vstd.graph.diagnostic.guilt` evaluation can establish `GUILT` after causal
  localization when an obligation string is repeated consistently in the proposition.
- **Governing proposition:** `GUILT` requires separately bound, passing evaluations for
  responsibility or material contribution, obligation applicability, and violation of
  that same obligation. A compound mechanism may perform all three checks but must emit
  three separately bound component evaluations.
- **Smallest reproduced counterexample:** record a passing `RUST` event and causal
  localization, omit `BLAME` or another responsibility-component result, omit obligation
  applicability and violation results, then pass one exact-fact GUILT proposition carrying
  a decorative `violated_obligation` string. The current runtime returns `ESTABLISHED`.
- **Affected surfaces:** Graph assurance runtime and replay, the
  `VSTD-GRAPH-ASSURANCE-1` schema, normative and packaged Ladder text, architecture and
  claim-boundary documentation, generated API reference, tests, changelog, and pull-request
  review map.
- **Repair gate:** bind the final GUILT result to exact passing responsibility,
  applicability, and violation component digests; reject missing, failed, unknown,
  malformed, duplicate, conflicting, or neighboring components; embed and replay every
  component's evidence; then complete focused and full validation before returning TIME to
  `Status: CLEAR`.

When a contradiction is open, change the status to `Status: OPEN` and record the exact
coordinates, both incompatible claims, evidence for each side, and affected behavior. An
evidence-backed repair removes the resolved live entry and returns this file to
`Status: CLEAR`; Git history preserves the prior state. Development branches may remain
open. The tag-triggered publication workflow checks the exact tagged checkout and fails
unless this file contains exactly one `Status: CLEAR` line.
