# Pull Request Domain Explanation Language Native Version 2 Selection

Pull Request Domain Explanation Language (PRDEL) native version 2 is an opt-in
development candidate over one exact selected source snapshot. It is separate from
the historical `verifier-prdel-compilation-shards-2` ordered-vector successor. This
selection does not broaden or replace
`profiles/prdel-manifest-2-selection.json`.

JavaScript Object Notation (JSON), Secure Hash Algorithm 256-bit (SHA-256),
Unicode Transformation Format, 8-bit (UTF-8), and command-line interface (CLI)
names below retain their exact bounded meanings.

## Selected behavior

The selected native document route is:

- `generate_prdel_v2`, `validate_prdel_v2`, and `render_prdel_v2` in
  `runtime/prdel.py`;
- `build_source_bound_impact_graph` in `runtime/prdel_graph.py`;
- `partition_prdel_v2_document`, `compile_prdel_v2_shards`,
  `reconstruct_prdel_v2_document`, and `validate_prdel_v2_shards` in
  `runtime/prdel_v2_shards.py`; and
- the explicit `verifier-prdel-2` dispatch in `runtime/gate.py`.

Generation and validation recompute exact selected source and requirement bindings.
The source-bound impact projection keeps changed-reachable relationships and required
unresolved frontiers. Missing, dynamic, external, parse-bounded, traversal-bounded,
or output-bounded relationships remain `UNKNOWN`; prose cannot close them. Resolved
Python annotations include function, argument, and assignment type comments; an
unresolved or malformed annotation remains an explicit frontier. The private shard
transport partitions aligned obligation/record pairs while retaining the complete
impact graph in the manifest. A receiver preflights the per-artifact and aggregate
packet byte ceilings before shard hashing or decoding. Transport integrity is not gate
clearance.

Validation may also consume an independently selected
`verifier-prdel-replay-plan-1`. Its expected SHA-256 is supplied separately. The
plan contains only exact binding data, fixed pytest node identifiers, selected test
file digests, closed-catalogue frontier resolvers, and fixed limits. It cannot carry
an arbitrary command, import, pytest option, or claimed outcome. Verifier materializes
the exact head into a private temporary directory, runs the fixed node identifiers,
rejects skips, expected failures, zero tests, failures, errors, source mutation, and
stale bindings, and produces fresh replay results itself. Carried document evidence
never authenticates execution.

Every active unit, integration, regression, and preventative layer for every selected
obligation needs a fresh passing replay. A materialized frontier additionally needs a
matching claim and one of the closed resolver mechanisms. JSON and UTF-8 mechanisms
check exact selected bytes; replay selection alone is limited to represented dynamic
or unresolved relationships. Analysis, traversal, node, edge, source-size, parse,
frontier, and output bounds are not evidence-dischargeable. They remain `UNKNOWN`
until the graph is regenerated completely under an explicitly selected bound.

## Bounds

The selected implementation retains these ceilings:

- document: 33,554,432 bytes; description and aggregate packet: 67,108,864 bytes;
- version-two snapshot: 134,217,728 bytes; file: 33,554,432 bytes; abstract
  syntax tree (AST) source and inline changed-source material: 524,288 bytes;
- files and changed regions: 10,000 each;
- default source-bound graph: 10,000 nodes, 20,000 edges, 200,000 counted
  operations, and 8,388,608 output bytes;
- version-two CLI graph selectors are capped at 200,000 nodes, 400,000 edges,
  50,000,000 operations, and 33,554,432 output bytes; the same selection is used
  for generation and validation and is serialized in the recomputed graph;
- replay plan: 2,097,152 bytes, 64 checks, 256 total fixed node identifiers,
  512 selected test files, 1,024 reported tests, 10,000 exact-head files,
  120 seconds per check, and 2,097,152 output bytes per check;
- private transport ceilings: 40,000 analysis nodes, 200,000 analysis edges,
  20,000,000 counted operations, 33,554,432 output/artifact bytes, and
  67,108,864 aggregate packet bytes.

These are input, traversal, and materialization limits. They are not wall-clock,
universal memory, semantic-completeness, or runtime-correctness proofs. Exhaustion
does not become a passing result.

An exact changed artifact larger than the inline-source ceiling is represented by
its path, Git mode, byte length, and SHA-256 digest without copying its contents into
the PRDEL document. That representation establishes byte identity only. Its source
row retains `LARGE_EXACT_ARTIFACT_NOT_INLINED`, and language/schema meaning remains a
required frontier until a closed verifier replay discharges it. Version one retains
its historical 67,108,864-byte snapshot and 4,194,304-byte file ceilings.

## Unsupported capabilities

The base version-2 command-line interface (CLI) route supports native template
generation and exact validation. The dependent CLI overlay selected in
`PRDEL_NATIVE_V2_CLI.md` additionally supports exact version-2 rendering and private
manifest/shard validation. Version-2 rule compilation and authored definitions,
preventative comparison, impact-directed acyclic-graph tool output, and frontier
discharge outside the closed replay-resolver catalogue remain unsupported and fail
closed as `UNKNOWN`. The version-1 compiler in
`runtime/prdel_rules.py` remains version 1 and must not be cast as a version-2 compiler.

## Compatibility and claim boundary

`verifier-prdel-1`, `verifier-prdel-cli-1`, and the historical PRDEL manifest-2
ordered-vector contract keep their existing meanings and defaults. A version-1 document,
compiler envelope, report, or shard packet cannot carry version-2 source-bound meaning.
Cross-version substitution is rejected.

This selection binds exact bytes and declares a finite development-candidate surface.
Fresh verifier replay authenticates only the bounded selected execution used for
explanation-obligation fulfillment. Candidate test adequacy remains unestablished.
The result does not authenticate historical execution, establish independent-checker
status, requirement authority, semantic completeness, whole-estate impact completeness,
complete objective coverage, runtime correctness, workspace clearance, publication
clearance, human acceptance, release authorization, or overall safety.
Its semantic completeness is `UNKNOWN` and `release_authorized` is false.
