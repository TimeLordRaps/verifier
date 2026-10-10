# Bounded explanation compilation shards

Pull Request Domain Explanation Language (PRDEL); identifier (ID); JavaScript
Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256); command-line
interface (CLI); Unicode Transformation Format, 8-bit (UTF-8).

The opt-in `verifier.runtime.prdel_shards.compile_prdel_shards` route retains the
same independently selected commits, requirements, source obligations, supported
predicates, rule results and residuals as compilation. It serializes a separate
`verifier-prdel-compilation-manifest-2` parent and ordered
`verifier-prdel-document-shard-1` artifacts. The existing version-one compiler
and gate retain their single-document byte bound and behavior.

Manifest version two preserves the ordinary compiled document's exact
`source_obligations` order and its index-paired `records` order. The reader accepts
a legacy `verifier-prdel-compilation-manifest-1` packet only when its obligation
identifiers satisfy the original sorted unique invariant, and independent replay
reconstructs that historical sorting. A version-one packet cannot carry or be
silently reinterpreted as the version-two ordered-vector meaning.

Every artifact, including the manifest, must fit the existing 32 MiB document
ceiling. Snapshot, file, source-region, graph-analysis, explanatory-text, record
claim and rule-operation caps remain unchanged. Partition traversal consumes the
remaining rule-operation budget. A single oversized row or manifest, incomplete
source observation or exhausted partition budget yields no trimmed packet.

The parent retains the complete document header, including every impact-graph
frontier and exact binding, and the complete compilation header, including every
required and optional residual. Each obligation and corresponding record occurs
exactly once across deterministically ordered shards. All selected source IDs
are listed explicitly; digest, byte count, order, binding, omission and duplicate
checks precede reconstruction. Reconstructing an intact packet establishes only
retention. `validate_prdel_shards` must independently replay the exact source and
selected inputs before reporting the compilation status. Known failures and
required UNKNOWN findings remain blocking; optional author motivation remains
optional. No source scope or predicate meaning is changed by partitioning.

A caller serializes the manifest and each shard separately as canonical immutable
bytes; the returned Python container is not one enlarged serialized document.
The version-one gate retains its existing single-document admission contract.

## Selected sharded description contract

The separate `verifier-prdel-shard-description-1` contract requires an externally
selected manifest SHA-256, every ordered shard SHA-256, exact base/head/source and
requirements digests, and the complete selected required compilation residual
inventory. `render_prdel_shard_description` and `evaluate_prdel_shard_description`
independently replay compilation and run logical source checks. Canonical shard
order is the exact compiled obligation/record pair order; equal identifier sets
or counts do not establish equivalence. Every required compilation residual,
native FAIL/UNKNOWN finding and required NOT_RUN check remains retained. A changed
body, substituted packet, missing row or wrong selection cannot establish PASS.
Unavailable source remains UNKNOWN while known failures remain FAIL. Compilation
retention alone continues to report `Gate status: NOT_ASSESSED`.

The caller must select a positive integer `packet_budget_bytes`; missing or
invalid budgets fail closed. The retained-source receiver application profile admits at most
64 MiB total manifest-plus-shard bytes, matching the existing finite snapshot and
aggregate document receiver envelope. The selected total is admitted before
hashing or decoding. Every artifact also fits the smaller current compiler and
document decoder ceiling. These are representation bounds, not a runtime memory
proof. Leaf `max_operations` accounts for declared inventory traversal, separately
from parser work, replay, logical checks and wall-clock execution.

The local human-description policy admits at most 32 KiB of UTF-8, with tighter
`IndexLimits` allowed. Full native findings are retained or output is refused;
none are trimmed. Output exhaustion preserves any established FAIL. The JSON
schema declares the body type but does not encode this UTF-8 byte cap. Runtime
admission is authoritative; schema validity alone does not establish byte
admission. A character count is not a UTF-8 byte count. This byte policy is
conservative local admission, not a verified GitHub server maximum.
GitHub REST documentation declares a string body without a numeric maximum;
the Agentic Workflows safe-output gateway has its own character constraints.
See [REST pull requests](https://docs.github.com/en/rest/pulls/pulls) and
[safe-output specification](https://github.github.com/gh-aw/specs/safe-outputs-specification/).

The CLI selects this route explicitly:

```text
vstd gate pr --contract verifier-prdel-shard-description-1 --root REPOSITORY
  --base BASE --head HEAD --manifest MANIFEST --manifest-digest MANIFEST_SHA
  --shard SHARD --shard-digest SHARD_SHA --source-digest SOURCE_SHA
  --compilation-residuals SELECTED_RESIDUALS --packet-budget-bytes PACKET_BUDGET
  --render --json
```

Repeat `--shard` and `--shard-digest` in the same exact order. Rendering returns
the canonical body and separate assessment; successful rendering is a tool
operation. To validate, replace `--render` with `--file BODY`. Validation exits
0 for bounded PASS, 1 for FAIL, and 2 for UNKNOWN. Shard selectors require the
explicit new contract and cannot fall back to metadata checks or version one.
Optional selected requirements/evidence retain their paired digest requirements;
definitions replay through their existing selected compilation contract.

Qualified publication additionally requires complete selected machine artifacts
committed through the approved owner-preserving route, actual native evidence and
resulting-source qualification, final artifact selection and trusted acceptance.
Any later authorized posting must read back the exact intended body and artifact
references. This representation supplies no execution authentication, complete
relationship discovery, model correctness, overall safety or publication authority.
