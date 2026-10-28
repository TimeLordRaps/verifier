# Root-manifest package polish

Verifier Standard (VSTD) commands `vstd polish 1`, `vstd polish 2` and
`vstd polish 3` evaluate the **package GRAPH declared by objects.vstd in the
selected repository root**. The default root is the current working directory;
`--source-root PATH` selects another root. No package flag is required. The
command never searches a parent directory or substitutes specimen conformance
for package conformance. Before default root assessment, the installed
Verifier-specific refresh controller deterministically previews current source.
It either proves the manifest current, or retains external recovery evidence and
atomically replaces exactly `objects.vstd` before assessment. `--manifest-refresh
check` instead returns UNKNOWN on drift without writing or running a stale gate.
Cancelled, native-specimen, legacy `--package-graph`, and explicit alternate
Tier-0-manifest paths do not refresh. The assessor itself remains read-only.
The current GRAPH payload binds the complete non-manifest source-census coordinate.
An exact match takes a bounded bridge-validation fast path; only actual source drift
replays the full migration catalog. This keeps repeated polish preflight independent
of the number of graph obligations on an unchanged source coordinate.

The selected package `VERIFIER` is the self-polish subject. The typed `GRAPH`
remains its complete represented collection, but the execution receipt names the
aggregate `VERIFIER` as `subject_id` and binds the collection separately through
`verified_graph_id` and `subject_collection_digest`. Every evaluated obligation
is assigned to the unique namespace object that owns its exact checking-mechanism
surface. A non-`VERIFIER` primary kind participates as a member verifier only when
its `VERIFIER` classification is established for the selected source. The
resulting member-verifier graph is summarized cumulatively for each requested
tier. Source objects that own the polish implementation are also selected as
ordinary obligation subjects, so self-polish evaluates the polish system rather
than excluding the evaluator from its own denominator. The aggregate result is
never member evidence, and self-observation supplies no independent authority;
an unresolved member, polish-system obligation, reason, or dependency keeps the
aggregate result `UNKNOWN` or `FAIL`.

The production reason flow has exactly one authored input: the selected root
`reasons.vstd`. Polish first compiles the selected root `objects.vstd` and its
complete object-obligation denominator, then checks that single reason file
against the compiled obligations. Files under `tests/fixtures` are isolated
checker specimens, not additional production reason ledgers, and are never
combined with the root reason file into a package verdict.

That fast path requires the exact compact version-6 transport
(`verifier-objects-manifest-6`). A source-matched inline version-5 root is not
CURRENT: a source census certifies source only, not transport. Check mode reports
it as REFRESH_REQUIRED with the read-only blocker and the explicit reason
`MANIFEST_REFRESH_FORMAT_UPGRADE_REQUIRED`, and writes nothing. The default
automatic mode previews one complete compact version-6 candidate, binds it to the
opening source census, passes the package selector, and installs it atomically
after retaining the exact prior bytes externally. The next run is CURRENT with no
write. A candidate that stays inline is refused with
`MANIFEST_REFRESH_CANDIDATE_NOT_COMPACT_V6`, and the original bytes remain intact.
The controller recaptures both the source coordinate and manifest bytes after
bridge validation before returning `CURRENT`, so a concurrent writer cannot race
the fast path. `objects.vstd` remains the maintainer-authored declaration authority:
a source-unchanged, schema-valid manual declaration edit proceeds to the actual
polish assessor rather than being silently overwritten by refresh.

Refresh success is an exact receipt contract, not a trusted status string.
`CURRENT`, `NOT_APPLICABLE`, and `REMIGRATED` permit assessment only when the
complete versioned receipt, digest relationships, provenance booleans, and
outcome-specific recovery fields validate. A missing, unknown, widened, or
malformed success outcome fails closed before any stale assessor is called.
When refresh blocks the command, the command emits
`verifier-polish-manifest-refresh-blocked-1`, not the refresh producer's schema
and not a package-polish report. `refresh_outcome_schema_version` and
`refresh_outcome_status` preserve the producer's original labels explicitly.
The command-owned envelope self-seals its exact body, reports Tier 0 assessment
as `NOT_RUN`, and for requested Tiers 1–3 retains every cumulative package tier
and native Tier 0 through the requested tier as `NOT_RUN`/UNKNOWN with a
`NOT_RETAINED` denominator. This is mechanically bounded failure accounting;
it establishes neither admission nor polish.

The GRAPH also owns a source-semantic profile for every path supporting a reviewed
applicability decision or completed obligation. Each entry names the affected
object, classification and obligation identifiers. Python and stub sources use a
location-free standard-library abstract syntax tree digest, so comments,
formatting and line movement can rebind automatically. Other source types remain
byte-exact until a selected language extension supplies a bounded semantic parser.
Repeated object/question sets are interned once and referenced by bounded integer
indexes, avoiding per-path duplication inside the GRAPH payload.
Changed semantics, unavailable paths, or added/removed reviewed bindings return
`MANIFEST_REFRESH_REVIEW_REQUIRED` under `--manifest-review-policy refuse`;
automatic refresh cannot inherit the old answer or create the one-time profile
selection. The default policy, `record`, regenerates instead: each reviewed answer
whose cited source changed meaning is reopened (its applicability decision becomes
UNRESOLVED and its obligation loses its authored text), the semantic profile is
rebuilt over the answers that remain, and every unanswered question stays in the
regenerated `objects.vstd` as UNKNOWN for assessment to report. Nothing is refuted
or approved by recording. Corruption still refuses under both policies: evidence
citing a file its object does not own, a dropped profile, or a weakened answer that
was not reopened.

Publication serializes cooperating refresh writers with an exclusive external
lock. It prepares and fsyncs the candidate before immediately recapturing source
and target state, preserves a competing target, and emits a non-committed
`PUBLISHED_STALE` receipt if closing validation changes after replacement.
Portable file replacement is not compare-and-swap against an arbitrary writer
that ignores the lock; that narrow final race remains an explicit operating-system
boundary. Relative, absolute and same-file spellings of the root `objects.vstd`
select this path; only an actual alternate Tier-0 manifest bypasses it.

The retained manifest uses report `verifier-manifest-package-polish-1`; the
additive version-3, version-4 or version-5 manifest uses `verifier-manifest-package-polish-2`, preserving
the old report schema unchanged. JavaScript Object Notation
(JSON) output is selected with `--json`. Exit codes remain 0 for PASS, 1 for
FAIL, and 2 for UNKNOWN. `--cancelled` preserves this package report scope
without executing checks.

Package reports use 24 MiB as an ordinary-report projection target and retain
pretty-printed output while it fits the invariant 32 MiB hard wire cap. If only
formatting exceeds the hard cap, the command emits compact Unicode Transformation
Format, 8-bit (UTF-8) JSON with every
field, verdict and report digest preserved. Both measurements include encoded
text and the final newline. Crossing the 24 MiB target triggers at most two
best-effort lossless transport steps, from full rows to inspectable v2 references
and then to reconstructable v3 tables. A report that cannot use a step or cannot
shrink below the target remains an ordinary report while it still fits the 32 MiB
hard cap. Projection does not raise, bypass or reinterpret that hard cap. Large
version-5 graphs bind repeated object payloads to the selected manifest
and large PASS ledgers intern their complete reason and evidence definitions by
digest. The assessor first evaluates and consumes every full obligation row. Only
afterward may projection v3 encode blocker-free PASS rows as digest-bound entries
over first-use object and route tables, sorted semantic and checker definitions,
and their original source indexes. The independent publication validator must
reconstruct the exact ordered normalized row denominator, validate every per-row
and aggregate digest, and reject changed, duplicated, omitted, reordered, unused
or out-of-range table material. Every FAIL or UNKNOWN row remains expanded without
this PASS transport, at its committed original source index. Object identifiers
(IDs), kinds, edges and obligation coordinates remain reconstructable; no failed
evidence or blocker is hidden in a successful table. If the normalized report still exceeds
the 32 MiB hard cap,
the capacity report keeps a complete per-instance identity/status index, every
non-PASS blocker and focused action, and all actionable findings. It preserves
the original package blockers in addition to the capacity blocker; omitted bulky
PASS evidence bodies cannot become PASS. A `COMPLETE` capacity receipt also
retains the admitted GRAPH's exact object ID, declared kind and object-digest
ledger. Every compact obligation entry is checked against that ledger and the
installed route's tier, proposition, mechanism and scope before completeness is
claimed; a count-matching ghost object or similarly named route is rejected.
When the source report uses projection transport, the capacity receipt retains
the conditional-refutation count and digest in a commitment bound to that exact
`source_report_digest`; it does not duplicate the potentially large conditional
ledger. The named `REPLAY_FROM_DIGEST_BOUND_SOURCE_REPORT` transport requires the
source report bytes and fresh replay to reconstruct the ledger, and never claims
that the compact receipt contains the omitted row evidence itself.
If even that index cannot be constructed or retained within the active resource
or embedding limit, the minimal fail-closed receipt sets `denominator_status` to
`NOT_RETAINED`, keeps the result non-PASS and states that omitted rows are neither
passing nor inapplicable. Such a receipt is bounded failure telemetry, not a
complete cumulative polish report and not evidence for any tier's conformance.
The capacity step degrades in a fixed order, stopping at the first form that
fits, and names every withheld section in `omitted_sections`: (1) the full index
with every non-PASS blocker and focused action; (2) a grouped index that keeps
each entry's identity, status, normalized reason and rerun vector but drops the
per-entry action list, and folds findings that share a status, code and gate into
counted groups (`instance_count`, `object_count` and up to three exact `examples`,
with `omitted_finding_count` stating what the groups replace); (3) the grouped
index with the native-diagnostic non-PASS record list reduced to its
`nonpass_record_count`, marked `NOT_RETAINED`; and only then (4) the minimal
receipt. A group never merges a FAIL into an UNKNOWN, and FAIL groups sort first.
A selected check for a conditional non-trigger (`checker_status` `NOT_REQUIRED`)
is never replaced by a digest-bound reference during early transport compaction:
the denominator commitment digests the complete check, a reference is larger than
that check, and a recomputation from compacted rows must bind the same evidence.
Ordinary PASS checks are still factored into references.
If the complete source report itself cannot be canonically encoded, the receipt
sets `source_report_encoding_status` to `UNAVAILABLE` and leaves its digest and
byte count null; a digest of fallback metadata is never labeled as the source
report digest. When encoding is available, `source_report_digest` and
`source_report_bytes` always identify the canonical source-report body before
its `report_digest` self-seal is added, regardless of which size boundary caused
capacity normalization.
These digest-bound references are integrity coordinates, not independently
available source bytes. An offline consumer must also possess and hash-verify the
selected manifest/source report (or a qualified sidecar carrying those bytes)
before claiming current-source provenance from a capacity receipt alone.
Likewise, exact projection-v3 reconstruction establishes transport integrity only.
It does not establish that the full evaluated rows were truthful, that source is
current, or that a signer or application owner authorized any claim. Fresh source
replay or a trusted signature remains necessary for those distinct propositions.
Standard command output writes the checked bytes directly, avoiding platform
newline expansion.

A numeric polish command memoizes three pure functions of bytes that cannot change
while it runs: the installed 38-kind profile document, the source discovery of one
census (keyed by the resolved root and the census digest, so a changed byte is always
re-parsed), and the installed kind registry (built once per process; every caller
still receives its own dictionary, so a local extension never reaches another
caller). The first two are scoped to the command (entered by the numeric tier handler,
cleared when it returns) and hand each caller a copy; a refused build is never
retained. A source-owner scan indexes the discovered surfaces by path once per
assessment instead of once per owned path. None of these changes a verdict, a digest
or a report byte; they only remove repeated recomputation from whole-repository runs.

### Final publication-schema gate

The numeric package-polish command validates the exact final report selected for
publication, after pretty/compact serialization decisions and after any capacity
projection. The report must name one of the bundled package-polish schemas and
satisfy that exact schema. A schema-invalid report, an unsupported report schema,
or a bounded validator failure cannot exit 0 and cannot count as polish, even when
the rejected source report claimed PASS.

Rejection replaces the source report with the separately schema-bound
`verifier-manifest-package-polish-publication-rejected-1` receipt. The receipt is
UNKNOWN and non-authorizing: `whole_package_conformance` is `NOT_ESTABLISHED`,
`polished` is false, and release and deployment authorization are false. When
encoding is available, it binds the exact rejected source-report wire bytes by
Secure Hash Algorithm 256-bit (SHA-256) digest and byte count. It also binds the
selected bundled-schema digest when one was available, the validator-mechanism
digest when it was readable, a bounded validation-error ledger, and its own
self-digest. When a producer result cannot be represented as strict JSON, the
receipt instead records `source_report_encoding_status` as `UNAVAILABLE`, keeps
the unavailable source digest and byte count null, and names
`PACKAGE_POLISH_REPORT_ENCODING_UNAVAILABLE`; it never fabricates source wire
identity. These bindings establish only fail-closed publication rejection;
schema validity does not establish that the rejected source report was correct.

## Readable findings and one-object gates

Default numeric package polish reports each instance gap with its exact manifest
object identifier, registered coordinate, readable obligation identifier, blocking
gate, verdict, normalized reason, detailed explanation, next action and rerun
argument vector. The `reason` field is always present on a non-PASS finding; it
retains the exact diagnostic prose used by the human-readable output. An unavailable
input is UNKNOWN, not a failed process. A contradiction is FAIL. Repository-wide
failures have repository scope and no invented object identifier.

A missing or unadopted answer is UNKNOWN; only a contradiction is FAIL. For the
source-representation routes (`<KIND>-1.90` through `<KIND>-3.90`), a discovery
gap, an installed review answer the manifest has not adopted, and a specialization
label with no standing claim are all unestablished: they report UNKNOWN with the
exact gap, and they never mask a real contradiction (a reviewed label that is
missing, or an extra label that already has a non-open answer, still FAILs).
Polish never authors `DOES_NOT_APPLY` and never withdraws a label to clear a gap.

The admission-time semantic-review replay applies the same rule. It compares each
installed review answer with the manifest. A classification cell that source drift
reopened (status `UNRESOLVED`, no evidence) and an installed obligation whose binding
was blanked by the same reopening make no claim, so they report
`PACKAGE_SEMANTIC_REVIEW_UNADOPTED:<object>:<kind-or-obligation>` and UNKNOWN. A cell
or binding that differs while still carrying a claim, an obligation the installed
contract does not define, and a blank binding for such an obligation remain
`PACKAGE_SEMANTIC_REVIEW_*_CONFLICT` and FAIL. Unadopted answers sort beside, never
instead of, a real conflict, and the next refresh re-answers the reopened cells from
the installed audits.

When more than 24 findings remain, the human-readable summary prints counted
groups instead of one block per instance. Findings sharing a status, code and gate
collapse into one entry with the instance and object counts, the normalized
reason, one next action and up to three exact rerun commands; refutations print
first. Non-PASS records inside native diagnostics are grouped the same way, and
`--json` still carries the complete list. A blocked cumulative gate states its
reason with at most eight named instances, the total count and a digest of the
full list, never the list itself.

From the selected repository root, rerun a named instance with:

```console
vstd gate --object vstd-simulation --obligation SIM-1.1-declared-operand-facets
vstd gate --object vstd-simulation --obligation SIM-2.4-signed-transition-resource-records --json
vstd gate --object vstd-package-graph --obligation VSTD-T0.1-canonical-manifest-admission
```

`--source-root PATH` selects a different root. The gate validates the exact object,
kind and registered readable identifier, binds the imported implementation to the
source, and recaptures source and manifest after evaluation. Its report identifier
is `verifier-manifest-object-gate-1`. Existing `vstd gate` subcommands are unchanged
and cannot be mixed with these selectors. Exit codes are 0 PASS, 1 FAIL, 2 UNKNOWN.

Names supplement, never replace, the semantic version and proposition digest.
In particular the registered signed SIM-2.4 route is not the distinct fresh-execution
variant. No similarly named route, process, or native fixture is substituted.
Manifest version 1 supplies structural records only: a structural target replays
the selected object's generic and typed facets against the declared collection,
including their negative and missing-evidence controls. Without explicit instance
selection, other checks return UNKNOWN with an evidence gate. Version-3 selection
below connects exact retained inputs, not automatic domain applicability. A Tier-zero
target evaluates shared admission prerequisites but reports only the selected
admission obligation; its PASS is not package or object-tier conformance.

The implementation adds no required runtime dependencies. Targeted instance gates
do not rerun cumulative native specimen suites or every other object's checks.
Admission includes [optional Tree-sitter JavaScript syntax discovery](EXTENSIBLE_NAMESPACE.md#optional-javascript-syntax-coverage).
That inventory does not execute the subject or resolve every dynamic interface.
The [markup census](EXTENSIBLE_NAMESPACE.md#markup-and-embedded-code-coverage)
also inventories source elements, attributes and embedded code without claiming
browser equivalence or generated-template coverage.
General cross-language execution, reusable dependency results and graph partition
scheduling are not implemented by this command. Those contracts must preserve
exact source, input, mechanism, policy and prerequisite bindings; graph cuts cannot
delete obligations or accept unverified boundary results.

### Execution-overhead requirement

The performance target is approximately tier-independent orchestration overhead
for the bounded supported estate, with additional elapsed time attributable to
the actual repository checks. It is not a claim of constant-time verification
for arbitrarily large graphs or general satisfiability problems. Cold discovery,
source binding, graph scheduling, checker execution and report generation must
be measured separately; identical-workload comparisons must expose repeated
prerequisite work. Reading and reporting a larger graph still has a nonzero cost.

A future execution plan must deduplicate shared prerequisites and invalidate
reusable evidence when its source, inputs, mechanism, policy, environment or
prerequisite bindings change. Fresh-execution obligations require fresh execution.
Partition results must establish compatible cross-partition constraints, not
merely pass in isolation. These are implementation acceptance criteria, not
claims that a cached or partitioned scheduler currently exists.

## Execution and evidence

The evaluator reads the exact root file, enforces strict canonical encoding and
the installed [Tier-zero manifest contract](TIER_ZERO.md), constructs its typed
objects and edges from those bytes, and evaluates the declared GRAPH. The
`installed_route` and `installed_mechanism` ownership rules must select the
same declared VERIFIER; it is bound to the executed package evaluator, graph,
source, manifest, requested tier and checking receipts. An ownership label does
not establish external authority or the VERIFIER's semantic correctness.

Each declared object is joined to every installed route of its effective kinds
through the requested tier. Composite manifests derive that set with the same source,
classification and consequence mechanisms used by Tier 0, including unrefuted
conditional hints. Independent declaration reconciliation also compares the
effective kinds, including native kinds with no added Tier-0 declarations.
Every resulting instance retains its object digest, coordinate,
checker, source-realization reason, assigned VERIFIER, applicability gap and
fulfillment status. Generic and typed Facets are replayed on the actual declared
records, including malformed-negative and missing-evidence controls. Absent
per-instance inputs for other routes are reported, never replaced with fixtures.

The `kind_requirement` records the exact trigger reasons and source census.
Deriving AGENT from a generic OBJECT adds AGENT checks; it does not convert that
record into an AGENT or supply its MODEL, HARNESS and ENV operands. Such checks
remain UNKNOWN with `PACKAGE_INSTANCE_TYPED_REPRESENTATION_UNRESOLVED` and an
exact focused gate command. Native generic record checks retain their explicitly
kind-agnostic contract; the route's registered kind rule governs compatibility.
The same derivation keeps undeclared ROBOT, FINBOT
and other refinements in `refinement_coverage`. Missing specialized contracts
are reported separately, never counted as implemented routes or waived by a
base-kind PASS. Missing discovery cannot establish an empty denominator.

### Contract aggregation and explicit semantic remainders

`kind_requirements.contract_coverage` is a versioned
`verifier-package-contract-coverage-2` assessment of the current invocation's
results. It independently reconstructs the required object/route pairs from the
installed catalog and the full derived kind set, including consequence-derived
roles and local extensions. Missing, duplicate, unexpected or incorrectly bound
results fail the aggregation gate. Each result must retain the actual object,
proposition, tier, checker and assigned VERIFIER. A finite PASS also requires
the selected checker and established applicability; optional status, a specimen
substitution or unresolved blockers cannot satisfy it.

Every version-2 ordinary, cumulative or capacity report carries the required
`kind_denominators` record. Its `object_kind_count: 26` and
`object_kind_denominator_scope: RETAINED_NATIVE_WIRE` bind the frozen native
wire denominator used by the 26-by-9, 234-cell grid and its 408 registered
route memberships. Its separate `installed_namespace_kind_count: 38` binds the
installed namespace: the 26 retained native kinds plus 12 first-class additions
that can also accumulate as consequential roles. The 38 count must not be
substituted into the native grid;
a 38-by-9 calculation is a denominator error, not an extension. An OBJECT,
BOT or SIM label never exempts an applicable consequential role, including a
physical ROBOT path or real-financial FINBOT path.
The reference implementation names these exact boundaries
`BASE_CORE_KIND_COUNT = 26`, `PACKAGE_ADDED_KIND_COUNT = 12`, and
`PACKAGE_KIND_COUNT = 38`, and emits their exact disjoint kind lists in the
package contract profile and Tier 0--3 contract matrix. A count-preserving kind
substitution therefore fails even when all three scalar counts still match.
The same partition contributes exactly 194 core routes (116 behavioral plus 78
source-adaptation) and 99 added-kind routes (63 behavioral plus 36
source-adaptation); both subtotals are independently audited.
Each profile keeps two mappings distinct: `obligation_route_mapping` names the
three exact per-tier focused-gate obligation identifiers that actually exist in
the source-route catalog, while `family_obligation_route_mapping` relates those
routes to the 62 semantic family obligations. A tier-collapsed `KIND-SOURCE-0.1`
family alias is never reported as the identifier of a focused gate row.

The installed denominator has 38 profiles: 26 core kinds and 12 added kinds (those
whose namespace contract sets `extends`). Tiers 1 through 3 contain 293 distinct
routes, split 105, 97 and 91 by tier. Each kind has exactly one source-adaptation
route per tier, so `114 = 38 x 3`. The 179 behavioral routes decompose as
`179 = 116 core + 63 added`:

| Route class (contract matrix) | Count | Members |
| --- | ---: | --- |
| `SOURCE_ADAPTER` | 114 | one per kind per tier (38 x 3) |
| `NATIVE_RECHECKER` | 113 | native behavioral routes with no adapter |
| `PACKAGE_EXECUTION_ADAPTER` | 45 | exactly `package_execution.catalog()`, including the 12 local-invocation-ledger routes |
| `ADDED_KIND_BEHAVIORAL` | 21 | 9 retained added-kind behavioral, 3 BOT agency-surface, 6 ROBOT/FINBOT agency-surface, 3 POLICY enforcement |
| **Total** | **293** | `114 + 113 + 45 + 21` |

The same routes read by kind group: core `116 = 113 native + 3 BOT agency-surface`;
added `63 = 45 package-execution + 9 retained added-kind + 6 ROBOT/FINBOT
agency-surface + 3 POLICY enforcement`. The 12 local-ledger routes are part of the
45, not an addition to it. Grouping by adapter name alone yields 57
execution-class routes (`45 + 12`, the 12 being the agency-surface and policy
routes); that is a grouping error, not a package-execution count.

The older figures are subtractions from this total, not alternatives to it. 281
equals `293 - 12`: it omits the 12 retained agency-surface and policy-enforcement
routes, so it is not a Tier 1 through 3 catalog total. The older 113 and 54 are
likewise `116 - 3 BOT` and `63 - 9 (ROBOT, FINBOT and POLICY)`. The Tier-0
admission ledger has 9 obligations and the profile obligations number 62 (26 core,
one each, plus 36 added, three each), so `71 = 9 + 62` family obligations and
`364 = 293 + 71` defined obligations. Those are separate denominators from the
route count and from the 408 registered route memberships.

Claim boundary: a catalog row is a registered route; a mechanism execution is one
bound, applicable run of that route; conformance follows only from a selected
result that passes against the exact object and applicability declaration. Each
selected PASS is bound to its exact `object_id`, `object_digest`,
`collection_digest` and registered route. Reusing a result for a different object
or source snapshot fails instead of satisfying the profile.

Each contract exposes exact clause identifiers, reasons, claims, mechanisms,
result digests and focused rerun commands. Aggregation failures instead name
`vstd polish N` as their rerun: checking one underlying clause cannot reproduce
the entire package's missing, duplicated or substituted result set. Earlier
assessment receipts may carry focused commands; they remain readable but those
commands do not independently recheck package aggregation.
When a complete successful aggregation would exceed the bounded wire-report
budget, the package report retains a digest-bound reference for every passing
object/kind contract and keeps every non-passing contract and denominator
finding expanded. Likewise, a large successful selected check may be retained
as a digest-bound reference only after the full check has been consumed by the
denominator assessment. The enclosing instance still carries its object,
coordinate, checker, applicability classification, reason, status and focused
gate target. These are transport normalizations, not skipped checks or evidence
promotion. A repeated successful route realization may use the same treatment:
its class, human explanation, adaptation decision, semantic digest, full digest
and byte count remain inline, while the focused gate reproduces the complete
mechanism, preserved-semantics, residual and falsifier lists. Non-passing rows
are never projected.
For a report that remains above the 24 MiB ordinary-report target after the
ordinary factored PASS-row projection, projection v3 may move those PASS
references into tables before the 32 MiB hard wire cap is reached. This is a
best-effort lossless transport step: a report that cannot use it or remains above
the target may stay ordinary so long as it still fits the hard cap. Its source-index
partition must cover the complete assessed denominator exactly once:
table entries cover blocker-free PASS rows, while `obligation_instances` contains
every other row in original relative order. Shared table definitions are permitted
only because the row-level `complete_instance_digest` and ordered
`source_instances_digest` make exact reconstruction and tamper rejection executable.
The v2 factored representation remains valid for smaller reports; v3 changes
transport capacity, not obligation meaning, evaluation order or PASS criteria.
Separate residual requirements expose native slot questions and any behavioral
meaning outside an installed profile. These residuals are review questions, not
fabricated numbered obligations or proof that a universal clause inventory is
complete. All 38 installed kinds have explicit profiles; local extensions and
other unprofiled refinements remain `UNKNOWN`, and no finite routes is never a
vacuous PASS. Normative coverage is `PASS` only for the exact installed
source-package variant whose complete cumulative profile passes. It does not
establish universal kind conformance, external authority, physical or financial
truth, release or deployment.

This is an internal aggregation check over freshly assembled results, not a
portable receipt importer or independent execution replay. The surrounding
package evaluator retains source/manifest recapture. Existing report versions
and historical receipt meanings are unchanged; the nested assessment has its
own version and digest. Its schema describes shape, not fulfillment.

Fresh cumulative source-native controls are retained separately as
`native_diagnostics`, including the fresh-execution SIM variant and Statics for
Tier 3. They exercise checking mechanisms, not the package's missing instances.
PASS there cannot make package polish PASS. Manifest bytes, source and executed
mechanisms are recaptured after replay; contradictions survive later outages.
The Tier-0 admission obligation ledger remains inline because it is small and
ubiquitous.

### Exact native execution prefixes

The requested package tier selects an exact cumulative native prefix. The
`native0-1` prefix selected by `vstd polish 1` retains native Tiers 0–1.
`vstd polish 2` selects `native0-2`, retaining native Tiers 0–2. The existing
`vstd polish 3` path retains native Tiers 0–3 as `native0-3`. The Tier-1 and
Tier-2 paths execute their fresh prerequisites in order. Every executed
prerequisite retains its
self-sealed report; its `tier_execution` record is separately sealed by
`execution_record_digest`, and the record's `evidence_digest` must equal that
exact prerequisite `report_digest`. This digest linkage detects omission or
substitution inside the retained prefix. It does not establish independent
correctness, external authority, or package-instance fulfillment.

Execution stops at the first fresh prerequisite whose status is not PASS. Every
later tier in the selected prefix remains epistemically UNKNOWN and is retained
as `NOT_RUN`, with no evidence digest and with the same blocking-prerequisite
anchor: tier, tier name, observed status, retained report digest and blockers.
The corresponding unexecuted prerequisite bodies are absent; a later execution
cannot appear beyond that first non-PASS boundary.

The full package-report schema fixes the exact prefix shape for the requested
tier: no missing or extra execution keys, and no unsealed execution records.
Runtime completeness validation additionally requires exactly the prerequisite
reports for executed tiers and their exact evidence-digest linkage. A capacity
receipt may claim `COMPLETE` only when it preserves that same prefix and runtime
relationship. Denominator completeness can therefore retain a non-PASS executed
tier and its explicit `NOT_RUN` tail; it does not promote that prefix, the package
tier, or the package GRAPH to PASS. Tier 3 keeps its existing `native0-3` Statics
and fresh-execution semantics unchanged; the explicit Tier-1 and Tier-2 prefixes
do not weaken or replace that contract.

A Tier-3 run records execution state for every native tier 0–3; when a failed
prerequisite makes dependent execution unsafe, those tiers remain epistemically
UNKNOWN and are explicitly `NOT_RUN` with the blocking tier, reason, blockers,
digest and rerun rather than disappearing from the report.
If package assessment stops after GRAPH admission but before package aggregation
or native replay completes, the Tier-3 report closes every missing package Tier
1–3 aggregate and native Tier 0–3 execution slot as explicit `NOT_RUN`/UNKNOWN
with the stopping stage and blockers. It does not fabricate a prerequisite
receipt or treat a retained partial row set as the complete denominator.
Human output enumerates this same tier-execution ledger and prints the retained
object, obligation, gate or coordinate, path, blockers and exact rerun argument
vector for each actionable native non-PASS record. If capacity telemetry did not
retain the native ledger, the output says the cumulative report is incomplete;
absence is never rendered as PASS.

## Current closure boundary

### Selected instance evidence

The version-3, version-4 or version-5 manifest's `namespace` may include an `instance_checks` array.
Each artifact-backed entry selects `object_id`, `coordinate`, `semantic_version`,
and `proposition_digest`, plus a repository-specific `reason` and source `evidence`
references. Its `request`, `policy`, and `certificate` fields each contain a
repository-relative `path` and exact `sha256`. The request and policy are canonical
JSON documents for the registered native checker; the certificate retains its
native bytes. No manifest-authored module, executable command, verdict or
non-applicability flag is accepted. Duplicate object/coordinate selections fail.
The current package-root GRAPH-3.1 adapter described below is the one bounded
exception: it is selected from the exact current root and collection rather than
from an active artifact-backed `instance_checks` entry.

The adapter compares the request with the selected object and, for collection
checks, the entire declared namespace collection. A passing certificate for a
different object or a changed referenced operand cannot count. Native replay
then validates the exact schema, policy, evidence and proposition. Unsupported
subject-binding formats remain UNKNOWN; no weaker fallback is chosen. Relative
paths cannot traverse outside the root, reference objects.vstd, or follow symbolic
links or Windows reparse points. Each file is bounded to 16 MiB and the assessment
snapshot to 64 MiB. Shared inputs are read once and all selected bytes are
recaptured before the result is finalized, including files ignored by Git.
Tier 0 checks these path and byte bindings without executing instance checkers.

Representation and typed-layout obligations are necessary for every declared
record. A current source-bound selection and exact native replay can discharge
that instance's bounded structural proposition. This does not establish payload
truth, physical/financial effects, or the source-to-runtime relationship.
The retained MARKET, ROBOT and FINBOT mechanisms add nine registered behavioral
routes. Their selected request, policy, certificate and owned source bytes replay
through installed checkers and bind the exact object and current collection. The
adapter does not actuate hardware, submit orders or move money. Other registered
checks execute selected retained inputs but retain `UNKNOWN` applicability until
their necessary/conditional predicate is mechanized. A missing exact selection or
source-bound refutation also remains `UNKNOWN`; hashes, reasons and a computational
PASS cannot invent that predicate. Missing or invalid selected inputs never fall
back to a passing structural check or native specimen.
Focused `vstd gate` reads only its selected instance; package polish shares that
replay path for artifact-backed selections and retains all other obligations and
coverage gaps.

### Current root dependency graph

Versions 4 and 5 can select an evidence-bearing current root GRAPH payload while
retaining its earlier role-template record separately. Version 5 changes only
the finite transport profile for complete package graphs. The current package
root has exactly the four registered GRAPH-3.1 statics fields plus
`source_refresh_coordinate` and `source_semantic_profile`. Its representation
update requires exact old/current record commitments, a repository reason and
current owned-source references. Existing kind and operand obligations remain.

When the root declares `scope=retained_directed_graph`, GRAPH-3.1 is necessary
for that bounded dependency-graph claim. The package adapter validates the exact
six-field current root, its representation update and the complete current
collection. `package_graph_representation.py` deterministically reconstructs
every direct member and every member's operand dependency. The adapter checks the
declared node and edge commitments, projects only the native checker's registered
four-field statics payload into a transient GRAPH, substitutes that projection
into the complete current collection, and constructs canonical evidence, request,
installed policy and certificate in memory. It then rechecks the certificate with
the installed native mechanism and refuses any dependency omission or commitment
difference. The result records `PACKAGE_GRAPH_BOUND_FRESH_REPLAY`, the original
and projected object/collection digests, both source bindings, and the explicit
adaptation reason. Historical request, policy and certificate files are not read
or treated as current authority.

Maintainers may explicitly retire only the package root's historical GRAPH-3.1
`instance_checks` selection with `--retire-package-graph-instance-check`. The
migration refuses retirement unless the exact enriched payload, valid source
bindings and one refreshed, matching representation update with owned source
evidence establish the adapter basis. It leaves every artifact file and every
other object/coordinate selection untouched. This is not a generic GRAPH
selection replacement.

Neither this deterministic projection nor its PASS establishes source
authenticity, external authority, complete source/interface discovery, runtime
call edges, causal effects, whole-tier conformance or whole-package conformance.
The source-refresh coordinate and semantic profile remain bound by the original
object and collection digests but are not interpreted by GRAPH-3.1. Other domain
applicability remains unestablished until its own predicate is mechanized.

### Selected fresh local LEDGER and TRANSACTION executions

The current catalog adds twelve bounded propositions without changing the original
408 native route memberships or their receipt readers:

| Readable obligation | Actual check on the selected implementation |
| --- | --- |
| `LEDGER-1.1-local-record-identity` | Exact retained proposal and replay; wrong ledger/domain refusal. |
| `LEDGER-2.1-local-invocation-accounting` | Two distinct ordered records; duplicates preserve state and proposal bytes. |
| `LEDGER-3.1-local-readonly-recovery` | Read-only recovery distinguishes absent from committed state after uncertainty. |
| `TRANSACTION-1.1-local-input-preconditions` | Invalid digest, epoch and noncanonical proposal fail without insertion. |
| `TRANSACTION-2.1-local-commit-boundary` | Failure before commit rolls back; lost acknowledgement after commit preserves one row. |
| `TRANSACTION-3.1-local-replay-and-epoch` | Concurrent duplicate exclusion; stale epochs fail and consumed identifiers stay consumed. |
| `LEDGER-1.2-local-provisioning-continuity` | Reprovisioning preserves records; different ledger/domain/epoch metadata is refused. |
| `LEDGER-2.2-local-retention-boundaries` | Actual 4,096-record and 67,108,864-byte caps; exhaustion preserves state and known duplicates remain failures. |
| `LEDGER-3.2-local-record-integrity` | Five stored-field corruptions fail read-only replay/recovery; restoration restores replay. |
| `TRANSACTION-1.2-local-resource-selection` | Missing storage is never implicitly created; invalid identity, epoch or selection type is refused. |
| `TRANSACTION-2.2-local-cancellation-boundary` | Cancellation/interruption around commit remains uncertain; recovery distinguishes actual retained effects. |
| `TRANSACTION-3.2-local-epoch-transition-guards` | Invalid/stale transitions preserve state; advancing does not erase history or renew identifiers. |

Each includes its necessity reason and exact finite claim in the catalog.
Source-derived kinds add these obligations even when the primary label is OBJECT.
Absent or unsupported implementation selection remains UNKNOWN, not a specimen
fallback, inferred non-applicability or optional obligation.

`namespace.execution_checks` explicitly selects an installed implementation using
`object_id`, `mechanism`, `reason` and source `evidence` references. The supported
mechanism is `verifier-local-invocation-ledger-1`. Its selected object must own and
reference the exact `src/verifier/runtime/polish_invocation_ledger.py` source.
Every executable package dependency and the ledger specification must match the
installed bytes before a fixed child worker is launched. The worker ignores caller
import paths, site customization and cached package bytecode. A fresh nonce binds
observations to the selected object and full collection; source is recaptured.

The worker uses isolated temporary SQLite databases, four bounded concurrent
attempts and explicit backend fault injection. An independent parent predicate
checks persisted rows as well as returned statuses. A child status word alone
cannot establish the result. All twelve checks share one execution per object per
assessment; failures are shared too. The next assessment runs afresh. Timeout or
unavailable execution remains UNKNOWN. Neither repository code nor manifest-authored
commands or database paths execute. Tier 0 only validates and binds the selection;
it never launches the worker. A focused gate selects one proposition through the
same evidence path used by package polish.

The retention experiment directly seeds valid canonical proposal rows to reach
the actual configured boundaries, then executes ordinary consumption, exhaustion
and duplicate attempts. Seeding is fixture preparation, not evidence of thousands
of past production commits. Capacity constants are not lowered for testing. The
largest private fixture retains 64 MiB of proposal bytes; insufficient temporary
storage leaves execution UNKNOWN. Cancellation is injected at the database edge,
not by terminating a process. Integrity tests cover proposal bytes, proposal digest,
epoch, negative commit time and mechanism digest; they do not authenticate a
plausibly replaced authority-status digest or operator-controlled history.

This basic runner is not an operating-system sandbox or remote runtime attestation.
It assumes the configured interpreter and local operating system behave as claimed.
The proposition covers these exact finite executions, not all possible inputs,
production history, authenticated issuer authority, monetary accounting, distributed
finality or power-loss durability. The local ledger stores nonmonetary invocation
counts and proposal bytes. Other variants need their own mechanisms and applicability
evidence. Even twelve passing checks leave full refinement coverage and package
normative completeness unestablished; necessary broader obligations remain visible.

### Selected fresh manifest-publication TRANSACTION executions

`verifier-manifest-publication-1` selects the exact owned
`src/verifier/runtime/namespace_cli.py` implementation. The closed
`package_execution.py` registry dispatches installed mechanisms; no selection
contains a command, import name, or operator-resource path. Admission binds the
correct implementation for the selected mechanism without executing it. Higher
tiers use the same source-bound worker path as a focused gate.

| Readable obligation | Actual finite experiment |
| --- | --- |
| `TRANSACTION-1.3-manifest-input-preconditions` | Invalid inputs remain unchanged; preview returns canonical content without publishing. |
| `TRANSACTION-1.4-manifest-effect-scope` | Exact draft publication preserves source; formatting retains unverified evidence fields. |
| `TRANSACTION-2.3-manifest-publication-boundary` | Errors before/after replacement leave old/new bytes; an edit detected before replacement is preserved; unpublished temporary files are removed. |
| `TRANSACTION-2.4-manifest-partial-create` | Partial creation raises an error and retains partial bytes; retry refuses to overwrite them. |
| `TRANSACTION-3.3-manifest-retry-behavior` | Duplicate creation refuses; repeated formatting is content-idempotent and preserves unrelated files. |
| `TRANSACTION-3.4-manifest-concurrent-create` | Two synchronized creators both discover first; exactly one publishes and one refuses. |

The worker creates private fixture repositories with installed Git, in a private
working directory with user/system Git configuration disabled. It never runs the
fixture's source. Interpreter, installed Git and filesystem behavior remain host
assumptions; this is not an operating-system sandbox. Missing tools or resources
leave execution UNKNOWN. Independent predicates check bytes and retained effects,
not printed status text. File observations decode raw bytes without normalizing
line endings; byte-deviation regressions guard that observation boundary. Every
route carries its necessity reason and exact claim.

Exclusive creation does not make a whole write atomic: failure can leave a partial
new file. Formatting checks the original bytes before replacement, but that does
not exclude an arbitrary writer racing after the check. These limitations remain
explicit; neither the checks nor a canonical result supply power-loss durability,
universal race exclusion, path confinement, application authority or admission.

Selecting this mechanism does not discharge the local-ledger variant's routes,
and selecting the ledger cannot discharge manifest-publication routes. Unresolved
variant applicability remains UNKNOWN rather than an invented exemption. Full
refinement contracts and whole-package completeness remain separate requirements.

An object can select several installed mechanisms when it owns their distinct
implementation surfaces. Each selection needs its own reason and current source
evidence. A duplicate object/mechanism pair is rejected, even when its reason or
references differ. Execution observations and failed launches are cached by the
exact pair, not by object alone: one role's result cannot replace another role's
evidence. A focused gate launches only its selected route's mechanism. This
composition does not establish full-kind coverage or imply that every selected
mechanism is applicable; unselected obligations remain visible and unresolved.
The serialized selection shape is unchanged. Existing single-mechanism selections
retain their meaning, and earlier source-bound reports are not rewritten.

### Local worker protocol execution

`verifier-worker-protocol-1` selects the owned installed dispatcher in
`runtime/package_execution.py`. Its PROTOCOL role supplements the VERIFIER role;
it does not replace the original kind or reuse another object's evidence. Every
route has a necessity reason, exact finite claim and current-source binding:

| Obligation | Executed proposition |
| --- | --- |
| `PROTOCOL-1.1-fixed-worker-selection` | Two actual launches use a fixed worker, isolated interpreter flags, closed request fields and configured transport bounds. |
| `PROTOCOL-1.2-response-envelope` | Wrong schema, missing/extra fields, duplicate keys, non-object output and invalid encoding refuse. |
| `PROTOCOL-2.1-fresh-exchange` | Actual exchanges have separate fresh nonces; stale nonce or substituted object/collection binding refuses. |
| `PROTOCOL-2.2-failure-without-retry` | Injected timeout and failed exit yield no reply and no automatic repeat attempt. |
| `PROTOCOL-3.1-executable-source-binding` | Missing selected source prevents launch; substituted peer pins or changed final source recapture refuse. |
| `PROTOCOL-3.2-response-capacity` | A valid response at 1,048,576 bytes is accepted; one byte above is refused. |

The fixed private worker executes the real dispatcher and two actual ledger-worker
peers against temporary databases. Malformed peers and transport failure are
injected at the subprocess edge inside that worker; they are not live remote
participants. Independent parent predicates inspect recorded requests and outcomes.
This checks the local exchange implementation, not distributed consensus, host
authentication, protection from arbitrary runtime monkey-patching or confinement.
The response-size check follows subprocess capture and does **not** bound capture
memory. Timeout behavior relies on the host subprocess contract. All these limits
remain visible; a finite route PASS cannot replace complete PROTOCOL coverage.

### Parent-side execution observations

Every selected fresh worker execution now has a separate parent-side exchange
record. `execution_observations` retains each attempted exchange once in a package
or focused-gate report; each selected check links it by
`parent_observation_digest`. Worker response envelopes and historical receipts
retain their existing meaning. Older reports without this additive field provide
no parent-capture evidence.

The recorder retains exact submitted input and up to 1,048,576 response bytes,
plus at most 65,536 diagnostic-stream bytes, encoded without newline or Unicode
normalization. Full observed byte lengths and digests accompany explicit
truncation flags. Unavailable output is distinct from observed empty output;
timeout output is explicitly incomplete. Failed launches, nonzero exits and
refused responses retain their observations without authorizing a retry. Missing
selected source prevents launch and therefore produces no exchange record.

Before a current execution can supply a bounded route PASS, the evaluator checks
the parent's selected mechanism, object, full collection, challenge, source pins,
fixed worker, flags and environment-key inventory. It reparses retained response
bytes and requires the exact worker report used by the domain predicate. Missing
capture remains UNKNOWN; contradictory bindings or interpretation fail. Reasons
and failure-path controls accompany this mechanism in
[`package_execution_observation.py`](../runtime/package_execution_observation.py)
and its regression tests.

This is evidence from the running parent's subprocess interface, not independent
host attestation. Submitted input does not establish child receipt. Child file,
network, descendant-process and external-effect channels are explicitly
unobserved; no confinement or whole HARNESS obligation is discharged by this
record. Retention limits apply after capture and do not bound subprocess memory.
Existing original-kind obligations and package conformance remain required.

For Verifier's own package, `package_harness_applicability.py` checks the manifest-owned direct
process-launch applicability denominator at 32 sites: 30 ordinary subprocess
launches and two embedded language-worker launches. The mechanism is selected only
when the manifest gives its checker path exactly one owner whose accumulated
declared roles include `HARNESS`. Exact byte, whole-source abstract syntax tree
(AST) and call AST pins
make additions, removals, changed call shapes, or other semantic source edits fail
closed. Default polish remigration absorbs only comments, formatting and source-line
movement that preserve those AST bindings and every reviewed reason and gap. The enumerated Python vocabulary is
not an exhaustive native or third-party process detector: dynamic aliases refute
the scan, and recognized `multiprocessing.Process.start` sites are reported outside
the denominator rather than omitted. The resulting report establishes only this
bounded applicability classification. It does not establish that a launch
occurred, that descendants or effects were confined, or that the full `HARNESS`
obligation surface passed; other repositories remain unselected until they supply
their own mechanism.

### Recorded provenance policy execution

`verifier-provenance-policy-1` selects the owned installed `data/policy.py` engine.
The POLICY role adds to its owner's existing roles. Its applicability is the
selected implementation's actual decision boundary, not the name of an arbitrary
policy file. Fresh private in-memory graphs exercise all three public predicates;
the parent checks a separate finite truth table and exact decision encodings.

| Obligation | Executed proposition |
| --- | --- |
| `POLICY-1.1-provenance-input-scope` | Exact target/rule identities; unrecorded targets are indeterminate. |
| `POLICY-1.2-provenance-rule-defaults` | All 36 pairs of six status classes distinguish no-revoked from all-valid; unrelated revoked records do not affect the target. |
| `POLICY-2.1-provenance-decision-encoding` | Each result encodes the target assertion and both recorded members' dependencies and facts, not only a verdict word. |
| `POLICY-2.2-license-selection` | Seven default/custom/empty selections distinguish missing rights, rejected source licenses and non-root target metadata. |
| `POLICY-3.1-incomplete-lineage` | Dangling lineage refuses; a rootless cycle cannot establish source-license approval. |
| `POLICY-3.2-encoding-contradiction` | Positive/refuting control certificates recheck through the kernel; solver/direct contradictions and incomplete or duplicated grounding refuse. |

Every proposition carries its own necessity reason and exact finite claim in
[`provenance_policy_execution.py`](../runtime/provenance_policy_execution.py).
The controls are not submitted provenance evidence. They establish neither the
truth of graph metadata nor ownership, license validity, policy authority or
downstream enforcement. The engine returns decisions, not an effect interlock.
The source-bound isolated worker has no operator dataset or external authority
input. Full-kind semantic remainders and package admission remain required.

For this repository, `scripts/migrate_package_manifest.py --select-provenance-policy`
adds the reviewed role, declarations and execution selection only when the owned
source matches the install. It refuses conflicting prior answers or selections;
automatic refresh replays this policy only when the manifest already selected it.
It cannot create an initial opt-in, replace a conflicting decision, or promote a gap.

### Fresh resource measurement and sensor execution

`verifier-resource-measurement-1` checks the owned fresh simulation (SIM) resource
pipeline as both MEASUREMENT and SENSOR. Its measurements are executing-thread
central processing unit (CPU) nanoseconds and peak traced Python allocation bytes,
not total device time, resident memory or physical measurements. Two real source-loaded
acquisitions run a two-transition trajectory. Separate injected controls exercise
the same installed capture validator and meter; a parent oracle checks the results.

| Obligation | Executed proposition |
| --- | --- |
| `MEASUREMENT-1.1-transition-resource-meaning` | Actual method/interpreter, ordered state bindings and metric types; altered identities refuse. |
| `MEASUREMENT-2.1-fresh-step-correspondence` | Distinct acquisition challenges/run identities; stale workload, challenge and state bindings refuse. |
| `MEASUREMENT-3.1-invalid-resource-records` | Missing/extra steps, invalid types/ranges and extra fields refuse; unavailable execution produces no capture. |
| `SENSOR-1.1-acquisition-source-binding` | Loaded and selected sources agree; substitutions, stale selection and changed recapture refuse, including numeric aliases for boolean package flags. |
| `SENSOR-2.1-transition-sampling-interval` | Validation precedes acquisition; known instrument inputs give elapsed differences and peak rather than current bytes; every step stops tracing. |
| `SENSOR-3.1-acquisition-fault-cleanup` | Clock, transition and tracer-read faults stop tracing without returning a capture; invalid trajectories never start acquisition. |

Reasons and exact finite claims live beside their checker in
[`resource_measurement_execution.py`](../runtime/resource_measurement_execution.py).
Controlled clocks establish software interpretation, not clock accuracy or physical
calibration. Readings trust CPython, its standard library and the invoking host.
Wall-clock age, external transducer calibration, uncertainty bounds, hostile-host
attestation and full kind conformance remain unestablished. These six propositions
do not replace retained signed resource-record semantics or SIM obligations.

`scripts/migrate_package_manifest.py --select-resource-measurement` explicitly
selects both roles on the actual owned meter, with six source-reviewed admission
declarations. It checks the installed validator, meter and bootstrap bytes and
refuses conflicting prior decisions before changing either role. The declarations
explain missing guarantees rather than certifying them. Automatic refresh may
rebind this already selected review to current exact bytes; it never creates the
initial role selection.

### Fresh TOKEN-backed ASSET execution

`verifier-token-asset-1` adapts the reviewed TOKEN implementation to three
cumulative ASSET routes. `ASSET-1.1` binds capability identity, units and integer
precision; `ASSET-2.1` replays issuance, suspension, revocation and the explicit
redemption boundary; `ASSET-3.1` reconciles finite delegation encumbrances without
widening scope, time, quota, caveat or soulbound restrictions. A fresh isolated
worker returns observations, and the parent rechecks their installed certificates
and negative controls rather than trusting its verdict.

`scripts/migrate_package_manifest.py --select-token-asset` is the explicit initial
selection. It adds the ASSET specialization, source-reviewed declarations and an
`execution_checks` entry only for the actual source owner. Automatic refresh can
preserve and rebind an existing selection but cannot create it. Issuer authority,
signature validity, real custody, holding completeness, redemption, application
enforcement, supply conservation and backing remain `NOT_ESTABLISHED`; these
routes are not complete ASSET conformance or package polish.

### Fresh simulated CONTROLLER and ACTUATOR execution

`verifier-emulated-control-1` runs one reviewed reference emulator through six
cumulative routes. `CONTROLLER-1.1`--`3.1` cover command/feedback identity,
finite timing and capacity, and rollback or recorded reset intervention.
`ACTUATOR-1.1`--`3.1` cover simulated command-to-effect events, saturation and
input/failure interlocks. The worker uses temporary software state; the parent
checks raw events, refusals and unchanged-state controls.

`scripts/migrate_package_manifest.py --select-emulator-control` explicitly adds
both roles, their source-reviewed declarations and the shared `execution_checks`
selection to the exact emulator owner. The mechanism is simulated-only. It does
not establish a physical effect, physical calibration or stability, hardware
attestation, real-world actuation, a physical safe state, complete kind
conformance or package polish.

### Retained MARKET, ROBOT and FINBOT instance execution

`verifier-retained-added-kind-behavioral-1` adapts nine retained native routes:
`MARKET-1.1`--`3.1` cover order/access lifecycle, matching/pricing/allocation and
settlement/disruption; `ROBOT-1.1`--`3.1` cover the declared
AGENT-HARNESS-CONTROLLER-ACTUATOR path, physical-reach observation records and
hazard intervention; `FINBOT-1.1`--`3.1` cover the declared agent/harness authority
scope, typed financial exposure and decision/effect/retry reconciliation.

There is no migration flag that manufactures these retained evidence claims. Each
route needs an explicit `namespace.instance_checks` request, policy and certificate
selection with exact source evidence. Replay binds the registered route,
`object_id`, `object_digest` and current `collection_digest` before invoking the
installed MARKET, ROBOT or FINBOT checker. Missing bytes, selection, role,
applicability or exact source-bound refutation stays `UNKNOWN`.

The retained engine never actuates hardware, submits an order or moves money.
Venue or legal authority, fairness, manipulation absence, live matching or
settlement, real custody or balances, runtime correspondence, authentic physical
observation, causal attribution, external confinement, safety and recovery success
remain `NOT_ESTABLISHED`. A bounded route PASS cannot promote any of those claims.

### Package-wide closure boundary

The retained version-1 contract declares one record for each of the original 26
kinds and their typed layouts. Verifier's version-5 root preserves those historical
records while its extensible namespace admits the complete 38-kind registry,
including the consequential financial, measurement, control, protocol, policy,
ROBOT and FINBOT roles. Concrete repository objects and accumulated roles remain
members of one package GRAPH. An OBJECT label never erases a more specific role,
and a simulated label never refutes a real-world consequence path.

Tier 0 requires both retained-record and namespace admission. Higher tiers retain
one object/route obligation instance for every applicable base kind and
specialization. Each instance carries a necessity reason, repository-specific
applicability evidence, a named mechanism and a result. A conditional obligation
is discharged only by an evidenced non-trigger; it is not optional. Missing
applicability, evidence, routes or source bindings remain explicit UNKNOWN or FAIL
states. Nonempty annotations and native specimens cannot substitute for package
conformance.

This document does not confer package-wide polish. A tier is established only by
a fresh `vstd polish N` execution over the current source-bound `objects.vstd`, a
complete exact denominator receipt, and the absence of earlier-tier blockers.
No release, deployment, physical truth, financial authority or external authority
is inferred. Later tiers cannot repair unresolved earlier package obligations.

## Explicit diagnostics and compatibility

`--native-specimens` selects the former bounded numeric diagnostic contracts;
their wire identifiers and Python functions retain their meanings. For example,
`vstd polish 3 --native-specimens --json` runs the
[source-native Statics checks](SELF_POLISH_STATICS.md), not package polish.
Native evidence-selection arguments require that explicit mode.

`vstd polish 1 --package-graph` retains the separate historical nine-tier and
corrigibility [package ledger](PACKAGE_SELF_POLISH.md), including its candidate
card and owner-selection inputs. It is not required by the default command and
is not the new target-tier report. Its independent rechecker accepts its own
report identifier only; it must not be presented as a rechecker for this report.
