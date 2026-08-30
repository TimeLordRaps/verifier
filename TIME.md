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

### Thaw lineage can be manufactured from a self-consistent sidecar

- **Implementation coordinate:**
  `src/verifier/artifact_control/__init__.py::thawed_artifact_status` accepts a
  `VSTD-ARTIFACT-THAW-1` sidecar without an actual parent bundle. It recomputes the
  sidecar's self-derived `thaw_id` and compares the descendant only with the recorded
  `parent_artifact_id`.
- **Governing Standard proposition:** `standard/ARTIFACT_CONTROL.md` states that thaw
  requires a cleanly verified sealed parent, records that parent's exact artifact,
  content, freeze, and seal identifiers, and uses `THAWED_CLEAN` for a descendant that
  still matches the parent's initial artifact identity.
- **Public-reference proposition:** the generated `vstd artifact status` reference says
  it compares a thawed descendant with its sealed parent identity.
- **Counterexample:** a completely fabricated sidecar with no parent bundle can return
  `THAWED_CLEAN`. A legitimate sidecar can also have its `parent_content_id`,
  `parent_freeze_id`, and `parent_seal_ids` replaced and its unkeyed `thaw_id`
  recomputed while still returning `THAWED_CLEAN`.
- **Contradiction:** a self-derived `thaw_id` establishes only internal field agreement.
  It cannot establish that an actual sealed parent exists, that its coordinates are
  genuine, or that the historical copy operation occurred.
- **Required repair gate:** established `THAWED_CLEAN` status must require an actual
  supplied parent bundle, clean seal verification, exact agreement with every recorded
  parent coordinate, and descendant comparison using authoritative parent metadata.
  Sidecar-only agreement must remain `NOT_ESTABLISHED` or fail closed.

When a contradiction is open, change the status to `Status: OPEN` and record the exact
coordinates, both incompatible claims, evidence for each side, and affected behavior. An
evidence-backed repair removes the resolved live entry and returns this file to
`Status: CLEAR`; Git history preserves the prior state. Development branches may remain
open. The tag-triggered publication workflow checks the exact tagged checkout and fails
unless this file contains exactly one `Status: CLEAR` line.
