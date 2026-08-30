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

### Internal authoritative bundle members can inherit linked external bytes

At head `6b8fe413c1155f877efb2b557cb3ad51342872f1` and tree
`b67052abe008319e730b7fe2c0cfedfc3614e6f3`, the normative bundle boundary and
runtime behavior disagree:

- `standard/ARTIFACT_CONTROL.md` requires symbolic links and special filesystem
  objects to fail closed. Internal `bundle/freeze.json`, `bundle/seals`,
  `bundle/seals/*.json`, `bundle/payload`, and its inventoried descendants are
  authoritative bundle members whose lexical final entries must have the required
  ordinary object type; they cannot inherit bytes from symbolic-link targets.
- `_load_freeze` and its `_read_json_object` call parse `bundle/freeze.json` after
  dereference; `verify_frozen_artifact` separately reads those dereferenced bytes;
  `_seal_file_paths` accepts linked regular-file targets; and `seal_artifact` uses
  target-following existing-entry handling.

On Windows Subsystem for Linux 2 (WSL2) over ext4, replacing an otherwise valid
`freeze.json` with a link to its external original produced `SEALED`. Replacing an
otherwise valid seal envelope with a link to its external original also produced
`SEALED`, despite both authoritative bytes residing outside the represented bundle.

This does not change the accepted read-only alias policy for the caller-supplied outer
parent-bundle path or explicit thaw-record path: those aliases may resolve because the
actual bytes, seals, anchors, and bindings are subsequently verified. The contradiction
is limited to authoritative entries inside the bundle.

Repair gate: introduce role-specific lexical classification and strict reading for
internal manifests, the seals container, and seal files; preserve payload refusal and
outer read-only aliases; add Linux-effective regressions proving linked or dangling
internal members fail while ordinary freeze, seal, conflict, thaw, and alias behavior
remains intact; then complete the repository validation gates before returning TIME to
`CLEAR`.

When a contradiction is open, change the status to `Status: OPEN` and record the exact
coordinates, both incompatible claims, evidence for each side, and affected behavior. An
evidence-backed repair removes the resolved live entry and returns this file to
`Status: CLEAR`; Git history preserves the prior state. Development branches may remain
open. The tag-triggered publication workflow checks the exact tagged checkout and fails
unless this file contains exactly one `Status: CLEAR` line.
