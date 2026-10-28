# Tier 1 self-polish evidence replay

JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
Extensible Markup Language (XML); Java unit test report format (JUnit); uniform
resource locator (URL). This document specifies a bounded mechanical pytest
replay for selected Tier 1 evidence. It does not specify whole-tier conformance,
polished status, independent review, release, deployment, or any provider state.

## Claim boundary

`replay_self_polish_evidence` may return `PASS` only for this proposition:

> For every selected obligation, its exact positive, negative, and `UNKNOWN`-
> preservation pytest nodes were each collected exactly once and passed without
> skips or expected failures, against the manifest's exact selected source,
> test, and mechanism bytes, while those bytes and the selected Git coordinate
> remained unchanged before and after the bounded run.

The receipt always carries `polished: false`, `release_authority: NONE`,
`whole_tier_conformance: NOT_ESTABLISHED`, and `provider_states: OUT_OF_SCOPE`.
A test may assert negative or `UNKNOWN` behavior and still mechanically pass;
the manifest records those case kinds as coverage obligations, not as caller-
authored result statuses. A digest-shaped string is only a commitment candidate:
it contributes no evidence unless the mechanism reads matching bytes.

## Independent selection

The caller supplies canonical manifest bytes, an independently selected
manifest digest, an independently selected digest of the loaded replay
mechanism, and a separately selected obligation denominator. The denominator is
reported by digest but is not evidence. Each denominator identifier requires
the exact ordered case set `POSITIVE`, `NEGATIVE`, and `UNKNOWN`; one
obligation cannot borrow a missing case from another. Selector independence and
semantic adequacy remain outside this mechanism.

The manifest has exactly these fields:

```json
{
  "schema_version": "verifier-self-polish-evidence-manifest-1",
  "source_coordinate": {
    "repository": "selected origin URL",
    "revision": "selected Git object identifier"
  },
  "files": [
    {"path": "repository-relative path", "role": "SOURCE|TEST|MECHANISM", "sha256": "sha256:..."}
  ],
  "obligations": [
    {
      "obligation_id": "selected identifier",
      "case_kind": "POSITIVE|NEGATIVE|UNKNOWN",
      "node_id": "tests/test_file.py::test_name",
      "source_path": "selected SOURCE path",
      "test_path": "selected TEST path",
      "mechanism_path": "selected MECHANISM path"
    }
  ]
}
```

Files and obligations are canonically ordered. Every selected file is mapped by
an obligation, every obligation is in the separately supplied denominator, and
every node identifier is unique. Each obligation identifier must have exactly
three rows, ordered `POSITIVE`, `NEGATIVE`, then `UNKNOWN`, with one unique node
identifier per case. Missing, duplicate, substituted, or extra case rows are
rejected. The replay module itself must be a selected mechanism. Test files
whose basename begins `test_self_polish` are refused so an aggregate or evidence
replay cannot certify itself recursively.

## Fixed execution profile

The mechanism accepts no command, executable, option, environment, output path,
or prior result from the manifest. It invokes only the current Python
interpreter with `-m pytest` and a fixed argument profile. The exact selected
node identifiers appear after the option terminator. Repository configuration,
third-party plugin auto-loading, repository `conftest.py` files, the cache
provider, bytecode writes, and inherited pytest options are disabled.

The temporary plugin, base directory, trace, standard output, standard error,
configuration, and JUnit XML are created outside the selected repository. The
trace records exact collected node identifiers and setup, call, and teardown
outcomes. The trace and JUnit XML must agree with a zero process exit and the
complete selected denominator.

This is not a sandbox. Selected tests execute Python code, so the independent
selector must review and pin eligible test bytes before replay. The manifest
cannot replace the fixed runner with an arbitrary executable or command.

## Fail-closed invalidation

`FAIL` records a positive contradiction such as a malformed or noncanonical
manifest, missing independent pin, pin or byte mismatch, wrong Git coordinate,
path escape, unknown or duplicate obligation, unmapped file or obligation,
missing negative or `UNKNOWN` case, duplicate or changed collection, skip,
expected failure, unexpected pass, incomplete outcome, nonzero run, missing or
inconsistent JUnit XML, or selected source changing during execution.

`UNKNOWN` records an inability to complete the bounded observation, including
unavailable Git metadata, repository or process access failure, timeout, input
capacity exhaustion, output overflow, or unreadable bounded evidence. Neither
state can be promoted by a caller-supplied status string.

The bounded receipt reports the manifest, obligation mapping, mechanism, and
fresh evidence digests; the exact origin, revision, and selected-file-set
coordinate; collected, passed, failed, skipped, expected-failure, and unexpected-
pass counts; and bounded invalidator codes. Each obligation membership carries
its three exact case kinds and node identifiers, each case's source/test/
mechanism path and hash and mechanical status, an aggregate `PASS`, `FAIL`, or
`UNKNOWN`, and a `stable_replay_digest`. Membership `PASS` requires all three
cases to pass; a global run invalidator downgrades the membership.

The stable membership digest binds the manifest digest, obligation-mapping
digest, exact source coordinate and selected-file hashes, all three case kinds
and node identifiers, derived setup/call/teardown outcomes, membership status,
process return code, and invariant result counts. It deliberately excludes
test duration, temporary paths, output bytes, and raw JUnit XML bytes, so two
equivalent fresh executions have the same replay coordinate without being
represented as the same execution event. Any change to selected bytes, case
mapping, phase outcome, status, or counts changes this digest. The top-level
`stable_replay_set_digest` binds the complete set of stable membership digests
and the same aggregate invariant coordinate.

Raw `pytest_trace_digest`, `junit_xml_digest`, `stdout_digest`, and
`stderr_digest` values remain separately preserved under `run_artifacts` for
per-run audit. The top-level `evidence_digest` binds those run artifacts to the
stable replay set, and `receipt_digest` identifies the complete receipt. Those
two values are execution-event coordinates and need not repeat across
equivalent runs. The receipt contains no captured test output.

## Current integration boundary

The authoritative exact 45-membership Tier 1 obligation mapping is not embedded
in this primitive. The numeric Tier 1 adapter derives that denominator from the
installed inventory and invokes this replay directly. A run still cannot begin
until the caller independently supplies and pins the complete manifest and
mechanism digest, and a successful run remains only the installed-route evidence
subgate. Provider availability, provider receipts, hosted state, and provider
qualification are outside this primitive.

The Tier 1 integrator's hook is:

```python
receipt = replay_self_polish_evidence(
    manifest_bytes,
    exact_repo_root,
    expected_manifest_digest=independently_selected_manifest_digest,
    expected_mechanism_digest=independently_selected_mechanism_digest,
    expected_obligations=exact_45_membership_case_denominator,
)
```

`exact_45_membership_case_denominator` maps each exact obligation identifier to
`("POSITIVE", "NEGATIVE", "UNKNOWN")`; the manifest therefore selects 135
unique case nodes for 45 applicable memberships.

The integrator must independently require the top-level `status` to be `PASS`,
an empty invalidator list, the exact selected source coordinate and digests, and
one uniquely matching `PASS` membership with a non-null
`stable_replay_digest` for every entry in the 45-membership denominator. A
prepared ledger row's `independent_replay.receipt_digest` compares to that
membership's fresh `stable_replay_digest`, not to the volatile top-level
receipt or run-evidence digest. A prepared complete representation may compare
its evidence coordinate to the fresh `stable_replay_set_digest`. The integrated
representation must also bind the separate candidate-estate replay through
`estate_evidence_result_digest`; neither digest can substitute for the other.
The integrator retains the fresh route `receipt_digest` separately as the audit
identity of the execution it actually performed.

Repository/package candidate applicability is replayed by the separate
`self_polish_estate_evidence` mechanism after the exact census, applicability
ledger, and estate-authority subject have been established. Route replay
`PASS` cannot replace that per-candidate evidence, and estate replay `PASS`
cannot replace this exact 45-by-three route replay. Tier 1 remains
`NOT_ESTABLISHED` unless both bounded evidence surfaces and every remaining
registry, crosswalk, authority, dependency, interaction, and source-stability
prerequisite pass.

A blocked Claude or Antigravity review state remains recorded in the
integrator's provider coverage record, but it is not an invalidator emitted by
this primary replay and does not replace or veto independently obtained primary
evidence. Conversely, provider success cannot repair a missing or non-passing
primary membership.
