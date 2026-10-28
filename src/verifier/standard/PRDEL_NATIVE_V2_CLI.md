# Pull Request Domain Explanation Language native version 2 command-line interface (CLI) overlay

This additive development-candidate overlay depends on the retained ancestor
native-v2 source-selection profile at `profiles/prdel-native-v2-selection-1.json`,
whose exact Secure Hash Algorithm 256-bit (SHA-256) digest is
`c44b538287aaf79d5f3b12d948355cbe2cb9174a7038475e576361261923b3cf`.
It targets only the non-Git snapshot aggregate
`2312413c8610fc0e4a7f8fd147e3af4ac8c5d6e557ea77bfaadbd3261e6ecade`.
It does not modify or broaden the historical
`prdel-manifest-2-selection.json` contract.

## Selected render operation

The explicit `verifier-prdel-2 --render --document PATH` operation:

1. reads one bounded explicit version-two document;
2. obtains the canonical portable body only from `render_prdel_v2`;
3. passes those exact body bytes and that same document to
   `run_prdel_gate_v2`; and
4. returns the logical gate status unchanged.

With `--json`, the `verifier-prdel-cli-2` envelope carries both the exact
rendered string and the logical report. Without `--json`, standard output or
the selected output file contains exactly the rendered string. Rendering grants
no clearance separate from the carried logical report. An absent explicit
document remains `UNKNOWN`; a wrong-version or malformed selected document is
`FAIL`.

## Selected independent replay operation

Version-two render and validation may select `--replay-plan PATH` together with
`--replay-plan-digest SHA256`. The plan cannot select a command, module import,
executable, or pytest option. It selects fixed `tests/*.py::test_*` node identifiers,
exact test-file digests, exact source/requirements binding, closed frontier mechanisms,
and bounded execution limits. Verifier produces the result from a private exact-head
materialization. A copied `PASS` receipt in the PRDEL document remains unauthenticated
and cannot clear any active layer.

The same capped graph-limit selection is passed to generation and validation through
`--prdel-max-nodes`, `--prdel-max-edges`, `--prdel-max-operations`, and
`--prdel-max-output-bytes`. Defaults are 10,000, 20,000, 200,000, and 8,388,608;
hard caps are 200,000, 400,000, 50,000,000, and 33,554,432. The recomputed impact
graph serializes the selected values. A document generated under different limits is
stale, not silently regenerated under a larger profile. Supplying any graph selector
requires all four, and selecting a replay plan requires the complete explicit set.

## Selected private shard validation operation

The explicit version-two manifest/shard route requires:

- one manifest path and externally selected lowercase SHA-256 digest;
- ordered shard paths and one externally selected digest per supplied shard;
- the exact source digest selected independently of the packet;
- a positive aggregate packet allocation no greater than 67,108,864 bytes; and
- paired requirements/evidence bytes and digests when either is supplied.

The CLI reads each regular Unicode Transformation Format, 8-bit (UTF-8) artifact within both the existing 33,554,432
byte artifact ceiling and the caller's remaining packet allocation. It checks
the external manifest and shard digests, checks that the manifest's source
binding equals the independently selected source digest, and then calls the
existing `validate_prdel_v2_shards` implementation. That validator remains
responsible for canonical wire validation, ordered and complete recomposition,
deterministic repartition, cross-partition graph integrity, exact base/head
source replay, and the logical PRDEL-v2 result.

The CLI wrapper preserves these outcomes:

- exact transport plus logical `PASS` is `PASS`;
- exact transport plus logical `FAIL` is `FAIL`;
- an omitted selection, unavailable/read-limited artifact, exhausted valid
  caller allocation, unavailable exact source, or retained
  parse/frontier/analysis bound is `UNKNOWN`;
- malformed digests, reordered or substituted bytes, extraneous bytes,
  conflicting source/base/head binding, or an invalid caller profile is
  `FAIL`.

The nested `verifier-prdel-v2-shard-report-1` remains visible in the CLI
envelope. The stable `report` field remains a
`verifier-prdel-report-2`, preserving the existing CLI consumer boundary.

## Unsupported and compatibility boundary

This overlay does not implement version-two rule compilation, authored
definitions, preventative comparison, impact-DAG rendering, compiler residual
admission, frontier discharge outside the closed replay-resolver catalogue, CORE
registration, release selection, or any
optional publication contract. Those selectors remain explicit `UNKNOWN`
capability results and never fall through to version one.

The version-one generator, validator, render, shard handler, parser, dispatcher,
and public gate entry retain their selected source bytes and behavior. The
historical version-one and manifest-2 meanings remain separate. A version-one
document, report, compilation, or shard packet cannot acquire version-two
meaning through this overlay.

## Claim boundary

This is a source-bound development candidate with
`semantic_completeness: UNKNOWN` and `release_authorized: false`. Focused
local checks establish only the selected wiring, exact byte/digest handling,
status preservation, fixed selected replay, schema discrimination, and unchanged
selected version-one functions. A replay `PASS` establishes bounded explanation-
obligation fulfillment only. It does not establish candidate test adequacy, runtime
correctness, checker independence, whole-estate or objective completeness, workspace
clearance, whole-suite qualification, publication, release authority, or overall
safety.
