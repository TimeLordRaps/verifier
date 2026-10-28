# Extensible repository admission

Terminology: command-line interface (CLI); reduced instruction set computer (RISC).

Verifier Standard (VSTD) version-2 admission uses `objects.vstd` to describe actual
repository objects, not one artificial instance of every installed kind. It is a
new, bounded admission profile, not a reinterpretation of retained version-1
receipts and not evidence that polish tiers 1 through 9 have been completed.

## Start with the next unresolved question

Run `vstd template` in a Git repository to create a draft only when `objects.vstd`
does not already exist. Run `vstd template --json` to inspect a draft without
writing anything. Review the proposed objects and classifications, fill in reasons,
named declaration fields and current evidence references, then run `vstd polish 0`. The command reports the
object, exact obligation, reason, and next action. Use its printed `vstd gate
--object ... --obligation ...` command to inspect a selected requirement while
retaining package-wide prerequisites.

Edit the JavaScript Object Notation (JSON) with ordinary readable indentation. Before assessment, run
`vstd format --write` to canonicalize `objects.vstd`; without `--write` it prints
the canonical form without changing the file. Formatting rejects duplicate keys
and never changes labels, reasons, evidence digests or registry selection.

Version-2, version-3 and version-4 envelopes have an 8 MiB input ceiling so the
complete source inventory can coexist with retained package declarations; one
MiB is 1,048,576 bytes. Version 5 preserves the version-4 semantic contract but
selects a 32 MiB ceiling and a one-million-node structure ceiling for complete
package graphs that cannot fit the older transport profile. Version-1 and
unrecognized formats retain the 4 MiB ceiling. Version-1 through version-4 and
unrecognized formats retain the 250,000-node structure ceiling; version 5 alone
selects the larger structure profile. Exceeding a bound refuses
assessment: it never truncates interfaces or removes obligations. Canonical
encoding and portable-value checks still apply. Independent reconciliation uses
a 16 MiB aggregate-input bound normally and a finite 64 MiB bound only for a
selected version-5 package envelope.

The template does not import repository code, manufacture reasons, claim that an
unmatched kind is inapplicable, overwrite an existing manifest, or issue a receipt
for semantic correctness. Multi-role source files may need splitting into several
objects. Each discovered definition and export alias must have exactly one owner.

### Python export coverage

The non-executing abstract syntax tree (AST) census gives each name in a literal
`__all__` its own `python-export:<path>:<name>` identity. Owning the file or target
definition does not cover that alias. Local re-export chains resolve to their
terminal definition or `python-binding:<path>:<name>` assignment, with current
target-source digest and inherited role declarations. Missing targets, ambiguous
module roots, cycles, conditional definitions and mutable export lists remain
`UNKNOWN` discovery gaps. Python discovery imports neither the subject nor its
optional dependencies.

Literal `_LAZY_EXPORTS` tables with `__all__ = list(_LAZY_EXPORTS)` are handled by
a closed dispatcher grammar in `runtime/namespace_exports.py`. It checks the
lookup, missing-name rejection, import/attribute selection and exact-name cache
write; table mutation, escape, rebinding or a different dispatcher cannot waive a
dynamic-surface gap. The supported empty deprecation table contributes no runtime
branch. This establishes declared source bindings only: it does not prove that an
import succeeds, that arbitrary runtime monkey-patching is absent, or that target
behavior meets higher-tier obligations. Other dynamic constructions stay unresolved.

Qualified and aliased builtin construction, dynamic import helpers, and escaped
construction capabilities remain explicit discovery gaps. The detector considers
possible imported bindings across scopes; shadowing is not a proof of absence.
Single-argument type inspection remains supported. This is bounded syntax
analysis, not a complete runtime call graph or a proof of confinement. The closed
lazy dispatcher exemption applies only inside its checked body, not to other
loader references in the module. A discovery gap names its unique declared file
owner and focused gate when available; ambiguous ownership is never guessed.

Unconditional metadata imports support unambiguous reader aliases. The bounded
inventory grammar resolves direct or module-qualified
`version`/`distribution` readers and exception-type references. Package names must
be literal or selected by tuple-unpacking loops over finite literal rows, a
non-escaped literal dictionary's `items()`, or its string/immutable-tuple values.
Mutated selectors, mutable nested values and unconstrained package names remain
unresolved. A distribution is either inspected directly or kept in one unshadowed
function-local binding with every use checked: reading `version` or `files`, or
directly calling `locate_file`, does not itself create interfaces.
Reader/distribution escapes, entry-point loading, reflection, rebinding and
conditional imports still retain gaps. Only exact checked references are covered,
never a whole module or a filename allowlist; other dynamic operations in the
same function remain subject to detection.
This closed source grammar does not execute metadata queries or prove import
success, installed-distribution provenance, host-hook behavior or confinement.
Recognizing a metadata read does not waive any source definition or export's
ownership requirement, nor another dynamic operation in the same file.

### Optional JavaScript syntax coverage

Install `python -m pip install "verifier-standard[discovery-javascript]"` in the
interpreter running `vstd`. The base package still has no required dependencies.
For a checkout, use `python -m pip install ".[discovery-javascript]"` instead.
The pinned Tree-sitter parser and JavaScript grammar run in a fixed Python
`-I` worker: repository modules, parser-name shadows and subject programs are
not imported or executed. Installed parser libraries are trusted local tooling,
not a sandbox for running the subject.

For `.js`, `.mjs`, `.cjs` and `.jsx`, templates inventory static declarations,
methods, fields, callbacks and separate `javascript-export:<path>:<name>` aliases.
These are syntax identities, not Python-style resolved target bindings or proof
that a runtime import succeeds. Literal module-level `const __vstd_kinds__`
arrays carry source roles; mutated, nonliteral or nested markers stay unresolved.
Reflective construction, property publication, runtime loading, cross-module or
wildcard exports, unresolved local aliases and embedded markup remain explicit
gaps. Parse errors never produce successful empty coverage. Other languages
still require their own adapters, independently of process-runner availability.

Reports bind the worker and actual parser-library bytes and recheck them before
closing admission or package replay. Node reconciles that selected binding but
does not independently rediscover JavaScript syntax. Missing dependencies,
unsupported versions, resource limits and timeouts preserve `UNKNOWN`.

### Optional Rust and shell syntax coverage

Install `python -m pip install "verifier-standard[discovery-rust]"` for `.rs`,
or `python -m pip install "verifier-standard[discovery-shell]"` for `.sh` and
`.bash`. Each grammar is independently optional; no required dependency is added.
Like JavaScript discovery, these pinned Tree-sitter grammars parse selected bytes
in a fixed isolated Python worker, not by importing the repository, invoking
Cargo, building a binary, sourcing shell files or evaluating commands.

Rust declarations, methods, named/tuple fields, enum variants, closures and
individual re-export names receive separate identities. Bash/sh functions,
assignments, command sites and redirections likewise need individual ownership.
Immutable top-level literal Rust `const __vstd_kinds__` arrays carry source roles;
mutable, computed, nested or otherwise ambiguous markers remain unresolved.
Known roles still accumulate, including those found in literal shell assignments.

Parsing does not generally expand Rust macros, procedural attributes, generated
includes or conditional compilation, resolve external modules/re-export targets,
or prove shell dialect equivalence. A narrow static resolver can close interface
*names* for exact Serde 1.0.228 derives and RISC Zero 3.0.6 `embed_methods`
relationships only when the invocation, crate manifests, lock checksums and Rust
toolchain are all present in the selected source census. Its receipt explicitly
excludes build success, generated values, dependency correctness, execution and
conformance. Every other expansion remains `UNKNOWN`, as do dynamic shell
dispatch, aliasing, `source` and `eval`. A parser failure is not empty successful
coverage. Neither syntactic ownership nor an installed process runner alone
closes generated interfaces or qualifies an obligation mechanism.

Reports bind the exact worker, parser runtime and grammar-library bytes and
recapture them before closing admission, package polish or focused replay.
Node reconciles the selected binding; it does not independently rediscover this
syntax. Missing one grammar does not discard evidence from another installed
grammar. Installation errors, malformed responses and timeouts preserve gaps.

### Markup and embedded-code coverage

Hypertext Markup Language (HTML) files and `.html.in` templates receive a
standard-library source census: each element, attribute, script block and event
handler has its own identity. Ownership of the file or enclosing element does
not cover omitted children or attributes. Literal `data-vstd-kinds` arrays use
JSON and inherit into descendants and embedded JavaScript; roles accumulate,
and duplicate or nonliteral labels cannot erase a consequential role.

Inline scripts and entity-decoded handlers use the optional JavaScript parser
above, in the same bounded batch as standalone sources. Reports bind their
decoded bytes and original-file location. Handler locations anchor to the
enclosing tag because entity decoding can introduce newlines absent from the
file. Source-relative script references bind selected file bytes; no resources
are fetched, and no runtime fetch or deployment equivalence is asserted.

The tokenizer is not a browser. Ambiguous nesting, foreign markup, custom
elements, embedded documents, executable addresses, nondefault encoding,
framework directives and unsupported script types retain explicit gaps.
Templates require generated-output evidence even when their static fragments
parse. Data scripts do not require a JavaScript parser, and plain markup adds
no dependencies. Interpreter and parser-source bindings are recaptured; the
independent reconciler binds the shared fragment/reference projection without
claiming independent browser execution or source rediscovery.

### Vector and workflow documents

Scalable Vector Graphics (SVG) uses a separate standard-library Extensible Markup
Language (XML) parser, not the HTML tokenizer. Elements, attributes, namespace declarations, script blocks
and handlers have individual source identities. Decoded script/handler bytes use
the optional JavaScript parser and inherit literal `data-vstd-kinds` declarations.
Locations anchor at the enclosing tag because XML decoding can change line breaks.
Document type declarations and entities are refused without resource access;
foreign contexts, animation, instantiated nodes, external style resources and
transformations remain explicit discovery gaps. Parser-wrapper and binary bytes
are bound and recaptured. Static syntax is not browser rendering or confinement.

Install `python -m pip install "verifier-standard[discovery-workflows]"` for the
optional pinned YAML Ain't Markup Language (YAML) parser. It runs in a fixed
isolated Python worker, composing syntax nodes without constructing subject
objects or executing commands. Duplicate/merged keys, aliases, custom tags,
multiple documents and capacity violations cannot silently select another step.
Repository modules cannot shadow the selected parser.

GitHub workflow jobs, steps, run blocks and action references receive individual
identities in addition to the YAML node census. Decoded command digests, declared
shells, and unambiguous local action/runtime source references enter the evidence
binding. This does not establish command-language interfaces: interpreter flags,
sourced files, expansion and generated behavior remain unresolved until their
adapters supply evidence. Expressions and remote actions are never evaluated or
downloaded. Composite and JavaScript action declarations are inventoried; other
action runtimes remain unresolved. Unrecognized YAML consumers are not presumed
passive merely because their files contain data syntax.

Admission and package replay recapture these parser selections. The independent
Node process reconciles the shared command/reference projection, not hosted
workflow behavior or an independently rediscovered syntax tree.

## Names cannot remove necessities

`OBJECT` is a general representation, not an exemption. The current registry has
38 installed kinds: the retained 26 and the following 12 first-class additions:
`LEDGER`, `TRANSACTION`, `ASSET`, `MARKET`, `MEASUREMENT`, `SENSOR`, `CONTROLLER`,
`ACTUATOR`, `PROTOCOL`, `POLICY`, `ROBOT`, and `FINBOT`. Each addition refines
OBJECT's general representation and has three named Tier-0 admission obligations.
Separately, all 38 kinds have installed Tiers 1--3 source-package variant profiles:
the core 26 bind 116 behavioral plus 78 source-adaptation coordinates and the added
12 bind 63 behavioral plus 36 source-adaptation coordinates. Those 293 coordinates
establish only the bounded installed variant when their conditions and evidence
PASS; they are not universal kind conformance. Local extensions and other
unprofiled variants remain `UNKNOWN`.

Each can be a primary kind or an explicit specialization. An OBJECT-based
specialization may accompany any original kind without removing its original
operand requirements. Thus a BOT may also declare ROBOT and FINBOT roles. A local
refinement of a narrower base still requires that base: a SIM refinement cannot
be attached to an unrelated kind. A repository can declare further refinements in `extensions`;
each names an already registered parent, a version, a reason, and new reasoned
obligations. Parents must precede children. Redefinition and inherited-obligation
removal are rejected. Local declarations are marked `LOCAL_DECLARATION`, not
standard-endorsed safety contracts. No extension imports or executes code.

The exact registry digest binds installed and local contracts. A new contract
requires a new digest and reassessment. The legacy `ObjectKind` enum and its
26-kind denominator remain unchanged for retained formats; the new registry is
not limited to those 26 names.

For a local extension, pass `vstd template --namespace-extension contract.json
--json`. The descriptor is a canonical JSON object containing `kind`, `extends`,
`version`, `reason`, and `obligations`. Each obligation has `id`, `name`, `reason`,
and `evidence_requirement`. Authors may supply `declaration_fields`, a nonempty
list of distinct lower-case field names; otherwise the required field is `contract`.
Every listed field requires an answer. For example, a `JOURNAL` extending `LEDGER` must retain
all three ledger obligations in addition to its own. Repeat the option in
parent-before-child order. The template calculates the exact registry digest.

Python source can explicitly declare `__vstd_kinds__ = ("LEDGER", "TRANSACTION")`
at module, class, or function scope. Descendant definitions inherit that source
declaration. This is observed evidence of a declared role, not proof of runtime
behavior. Missing compatible manifest labels are contradictions and cannot prune
the required obligation set. Names such as `Ledger` and paired operations such as
`commit`/`rollback` are only hints. Unresolved hints retain conditional requirements;
they never prove a mislabeled financial system.

Every refinement needs `APPLIES` or `DOES_NOT_APPLY`, a repository-specific reason,
and current source evidence. Missing support stays `UNKNOWN`. A source-declared
or manifest-declared role cannot be refuted by an annotation alone. A
`DOES_NOT_APPLY` is admitted as `DOCUMENTED`, never `ESTABLISHED`, only when four
conditions hold together. First, it has a repository-specific reason. Second, its
evidence binds the object's current owned bytes. Third, a fresh run of the installed
closure for its kind, within that closure's bounds, finds no registered boundary
identifier and no dynamic, external-effect or unsupported-language gate. No stored
record is needed: without one, the run covers the object's exact current owned
census, every owned file at its current census digest. A stored `EXECUTABLE_CLOSURE`
refutation witness, when present, must instead bind that object, kind, decision row
and installed mechanism, and the run covers its anchored census. Fourth, the
closed-effect audit of the object's full owned census, bound to the same digests, is
`CLOSED`, with no blocker, no external write consequence and at least one
substantive file. Data files (`.csv`, `.json`, `.md`, `.toml`, `.txt`) are scanned
for identifiers but cannot execute, so the audit reads only code. It reads Python
only, so an object that owns any other code is not admitted this way. `DOCUMENTED`
records the repository's negative interpretation of those bytes, not an
independently proven absence of arbitrary program behavior. It answers the
classification question but removes no obligation that a source hint selects, and
it never overrides a manifest-declared, source-declared or consequence-required
role. Any other `DOES_NOT_APPLY` is not admitted and blocks Tier 0: it stays
`UNKNOWN`, or `FAIL` for a boundary referenced in a bound witness's census, stale
evidence, a changed decision row or a forged witness. A boundary that a run without
a witness finds stays `UNKNOWN`, because no reviewer bound a claim for it to
contradict. An explicit `UNRESOLVED` classification with at least
one evidence reference selects that kind as a conditional candidate: its inherited
obligations remain in the denominator as `CONDITIONAL_UNRESOLVED`, without claiming
`APPLIES` or adopting the label. Stale evidence still retains that denominator and
fails freshness; an empty draft classification does not expand it absent another
trigger. The detector cannot prove that all semantic kinds have been found.
Dynamic/generated interfaces and external services require additional discovery
evidence; no universal completeness claim is made.

An exact source-owned decision may select `APPLIES` only to retain obligations
while expressly withholding subject instantiation, structural role evidence, or
an external effect. The consequence engine recognizes those demand-only cells by
their catalog-bound object, kind, and complete reason; a prose substitution or
stale digest cannot inherit that type. Their obligations and declaration fields
remain required, but they do not turn a verifier, reader, crosswalk, controller,
or delegated endpoint into its own AGENT, ROBOT, or FINBOT. Python materializes
the exact decision-digest binding consumed independently by Node.

## Financial admission obligations retained unchanged

| Identifier | Required declaration | Reason |
| --- | --- | --- |
| `LEDGER-0.1-authoritative-history` | Authoritative history, state, ordering, authority | Valid data bytes alone do not identify the authoritative accounts. |
| `LEDGER-0.2-accounting-invariants` | Units, balance rules, rounding, issuance and destruction | Valid entries can violate accounting invariants. |
| `LEDGER-0.3-correction-and-recovery` | Corrections, replay, reconciliation, recovery | Recovery can silently change relied-upon balances. |
| `TRANSACTION-0.1-effects-and-authority` | Affected resources, preconditions, authorization | Requests can conceal effects or exceed authority. |
| `TRANSACTION-0.2-commit-and-failure` | Commit, abort, finality, partial failure, compensation | Successful-path behavior does not establish failure behavior. |
| `TRANSACTION-0.3-retry-and-replay` | Duplicate handling, idempotency or its absence, retry limits | Duplicate delivery can repeat an external effect. |

Every applicable row requires both the installed rationale and the object's own
reason plus evidence references. Its `declaration` mapping must also answer the
exact named fields generated by `vstd template`:

- History: `history`, `state`, `ordering`, `authority`.
- Accounting: `units`, `balance_rules`, `rounding`, `sources_and_sinks`.
- Recovery: `corrections`, `replay`, `reconciliation`, `recovery`.
- Effects: `effects`, `preconditions`, `authorization`, `resources`.
- Commit: `commit`, `abort`, `finality`, `partial_failure`.
- Retry: `duplicate_detection`, `idempotency`, `retry_limits`, `replay`.

Missing or blank answers stay `UNKNOWN`, even with a valid source hash and reason.
Unregistered field names fail instead of silently accepting a typo. An unsupported
behavior must be explained explicitly, including why that boundary is appropriate;
omitting the field is not a non-applicability decision. These checks establish
answer presence and byte binding, not the truth or adequacy of arbitrary prose.
These are necessary admission declarations, not
executed financial-invariant tests. A `PASS` says the declarations and exact-byte
references are complete for this profile; it does not prove their prose, financial
correctness, regulatory compliance, independent authority, safety, or deployability.
Financial amounts in metadata use decimal strings; manifest numbers are bounded
portable integers. Referenced evidence retains its native representation.

## Added consequential admission contracts

The exact named fields and reasons are defined next to each obligation in
[`namespace_contracts.py`](../runtime/namespace_contracts.py). Templates expose
every required field without manufacturing an answer.

| Kind | Three admission surfaces |
| --- | --- |
| ASSET | Identity and quantity; issuance and redemption; custody and encumbrance. |
| MARKET | Orders and access; matching and allocation; settlement and disruption. |
| MEASUREMENT | Phenomenon and method; units, time and uncertainty; validity and missingness. |
| SENSOR | Acquisition and observations; calibration and envelope; sampling and faults. |
| CONTROLLER | Feedback and authority; timing and stability assumptions; intervention and failure. |
| ACTUATOR | Command-to-effect boundary; response and limits; feedback and interlocks. |
| PROTOCOL | Participants and states; ordering and replay; failures and progress. |
| POLICY | Rules and precedence; authority and exceptions; enforcement and decisions. |
| ROBOT | Agent-to-actuator binding; physical reach and observation; consequences and intervention. |
| FINBOT | Agent and financial authority; financial exposure and dependencies; decisions, effects and recovery. |

BOT is an AGENT situated in a SIM. ROBOT is an AGENT governed by its actual
HARNESS and connected through CONTROLLERs to physical ACTUATORs. FINBOT is an
AGENT responsible for consequential real-world financial decisions or effects;
delegated execution or relied-upon advice can matter as well as direct transfers.
These project definitions do not turn a non-agent controller into an AGENT or
ordinary computer resource use into robotic actuation.

BOT, ROBOT and FINBOT share observation, decision and action concepts, not
interchangeable consequence evidence. Roles accumulate: a simulated upstream
process cannot exempt a physical or real-money downstream effect. A mixed system
must represent both paths. Physical targets are not redefined as computational
ENV objects. Confinement requires evidence; a source label proves neither effect
confinement nor deployment safety. Current admission checks transitive reachability
and specialized ROBOT/FINBOT chains in a declared consequence graph. It does not
yet discover those edges from arbitrary source or prove runtime correspondence.

Control intervention is not proof of model corrigibility. Failure behavior must
justify stopping, holding or continuity within the claimed operating envelope;
immediate shutdown is not assumed universally safe. These answers do not supply
execution or physical validation. Every unresolved higher-tier mechanism remains
explicitly unestablished, even if all admission declarations pass.

### Consequence graph: bindings, reachability and control cuts

The namespace declaration may carry `consequence_graph` with
`schema_version: "verifier-consequence-graph-1"`, `edges`, and `effects`.
This is separate from historical `operands`: a feedback loop is not an invalid
dependency cycle, and merely referring to an object does not cause its effects.
Omission supplies no confinement or runtime-correspondence evidence.

Each edge has `source`, `target`, `relation`, `reason`, and `evidence` (current
`path`/`sha256` references, including a participating object's source). Relations:

- `embodies`: a ROBOT/FINBOT representation binds its actual AGENT. A BOT's
  native `agent` operand already supplies this edge and cannot be replaced.
- `controls`: an AGENT commands a CONTROLLER.
- `actuates`: a CONTROLLER commands an ACTUATOR.
- `decides`: an AGENT decides through a financial object.
- `influences`: an effect may propagate through advice, delegation or another
  dependency. It is not evidence of a governed control chain.

Each effect has `object_id`, `domain`, `reason`, and `evidence`. Domains are
`REAL_PHYSICAL`, `REAL_FINANCIAL`, and `SIMULATED`. A physical endpoint requires
ACTUATOR representation. A real financial endpoint needs the applicable LEDGER,
TRANSACTION, ASSET or MARKET kind(s); the mechanism cannot guess which from a
generic OBJECT. Multiple domains can coexist on one object. SIMULATED never
subtracts a real effect, and no `confined: true` assertion is accepted.
Those generic kinds do not establish a real-money endpoint when that same
object's exact FINBOT decision is demand-only and expressly withholds financial
effect. An explicit `REAL_FINANCIAL` declaration still remains authoritative,
and a typed financial object without such a demand-only boundary is unchanged.

Reverse reachability adds ROBOT and FINBOT requirements to affected agency
representations, including upstream BOTs. Relation types also impose endpoint
kinds even when the manifest calls them OBJECT. Missing labels fail; unresolved
or stale edge support cannot remove the requirements. Negative applicability
prose cannot override a declared path. Exact object gates retain global failures.

ROBOT checks require its actual AGENT's HARNESS and explicit controls/actuates
chains to physical endpoints. Cutting controls and actuates edges separately
detects parallel bypasses: one valid chain cannot hide an uncontrolled path.
FINBOT checks require its actual AGENT's governing HARNESS and path to a typed
real financial endpoint; delegation does not require a direct transfer.
For either role, every external-effect path from a wrapper must pass through
that same bound AGENT. An explicit embodiment or BOT operand cannot cover a
parallel bypass, including an effect on the wrapper itself. Reversed-domain
dominator trees check this without enumerating paths or repeating a traversal
per wrapper. Cyclic and indirect paths through the actual AGENT remain valid
for this structural proposition; missing reachability is not confinement proof.
Failures name the object's ROBOT-0.1 or FINBOT-0.1 obligation for focused replay.
Next-hop witnesses preserve inspectable routes.

The current package compiler has one source-reviewed route: the verifier witness
boundary `controls` the hardware CLI protocol, which `actuates` the accelerator
discovery command. The route is emitted atomically only when the core's governing
HARNESS operand and each exact APPLIES decision/evidence path are present. It is
not general edge discovery. Its accelerator endpoint is declared as a potential
`REAL_PHYSICAL` boundary because the reviewed vendor adapter may cross a
PATH-resolved executable boundary; that declaration does not establish command
selection, execution, authority, device access, occurrence, physical effect,
runtime correspondence, confinement, or safety.
The endpoint's demand-only ROBOT decision is not used as structural AGENT
evidence. The physical declaration instead requires the independent reviewed
controls/actuates route and the endpoint's source-established ACTUATOR evidence,
with both endpoint decisions bound to the same current source bytes.

These are mechanical checks of declared composition and current source bindings,
not operational authorization, deployment safety, financial correctness or proof
of confinement. Python and Node independently derive the extra kinds and
reachability witnesses; their shared source census is not independent discovery.

## Source and interpretation boundaries

Discovery reuses the bounded Git-tracked and nonignored working-file census.
Python definitions include classes, methods, nested and asynchronous functions;
file ownership does not implicitly own them. Unsupported languages and unknown
file types stay visible as `UNKNOWN`, not silent exclusions. No subject process
runs. The schema uses strict canonical JavaScript Object Notation (JSON), followed
by one line feed. The reader rejects duplicate keys, unknown fields, and ambiguous
numeric encodings. The JSON Schema is a shape aid; executable checks also enforce
registry inheritance, references, uniqueness, exact coverage and evidence bindings.

Python and Node independently derive per-object inherited obligation sets from
the same selected declarations and discovery observations. Node is required for
this agreement gate, not for template generation. This is not independent source
rediscovery. Missing Node leaves the gate `UNKNOWN`. Opening and closing source,
manifest and installed-mechanism bytes must agree.

Version-1 manifests must be migrated for the current admission path; they cannot
bypass classification by selecting an older declaration format. Default numeric
polish can perform that guarded step automatically only for a recognized
Verifier repository whose installed refresh engine exactly matches the selected
checkout. Retained version-1 assessment remains separately named for historical
replay. There is no automatic arbitrary semantic classification or automatic
higher-tier support for new kinds.

## Whole-package migration without dropping obligations

The version-3 package manifest retains all version-1 fields, changes only the
outer schema identifier, and adds `namespace` containing a version-2 declaration.
`package_manifest.py` requires every original object, payload and edge to survive.
Additional objects must be members of the same root GRAPH, never a disconnected
second inventory. The original obligation denominator remains 234 slots and 408
route memberships; namespace requirements are additional, not replacements.

Version 4 retains that historical contract but permits a current payload to
replace a role template in `namespace.objects`. Every changed retained record
requires one `representation_updates` entry: `object_id`, `retained_object_digest`,
`current_object_digest`, `reason` and source `evidence` references. Missing or
extra updates, mismatched commitments, changed kinds and removed operands fail.
The retained digest addresses the version-1 record reconstructed from top-level
`objects`; it does not assert ancestry from an arbitrary earlier current record.
Tier 0 checks current owned-source evidence and independently reconciles the
old/current binding. A reason is not proof of payload truth. Version 3 still
forbids payload changes; old receipts retain their meaning, and old collection
certificates cannot automatically satisfy the changed current collection.

Version 5 has the same representation fields and validation rules as version 4.
It changes only bounded transport capacity. The migration selects it when a
complete canonical result exceeds the version-4 byte ceiling, preserves it on
later refreshes, and refuses results above its own ceiling. Selecting version 5
does not make an obligation optional, establish evidence, or authorize excluding
a source surface for size.

`package_admission.py` executes both admission contracts on the selected root
bytes. Each of the original nine gates requires its retained check **and** its
namespace addition. Opening, intermediate and closing source captures must agree.
The report exposes both complete component receipts and the selected VERIFIER.
A standalone version-2 declaration receipt cannot discharge this package gate.

Tiers 1--3 consume that same graph and retain all original package-instance
obligations. Extra instances inherit base-kind checks. Every installed kind has an
explicit bounded source-package variant profile; a profile PASS applies only to
that exact current source variant. Local refinements and other unprofiled variants
remain `UNKNOWN`, and neither base checks nor admission prose fills their gap. All
12 added kinds also retain their three Tier-0 declaration contracts. The legacy
26-kind wire and its historical 408-route-membership denominator remain distinct
from both current 38-kind admission and the 293-coordinate installed profile
denominator.

The maintainer migration script previews by default and requires an exclusive
external backup for `--write`. It leaves unreviewed applicability unresolved and
preserves existing decisions rather than refreshing their evidence silently.
For versions 4 and 5 it also preserves current payloads and their exact update bindings.
Explicit `execution_checks` selections are preserved as well, never silently
added, refreshed or executed by migration. Bounded installed executions include
the six local invocation LEDGER/TRANSACTION propositions; three TOKEN-backed ASSET
routes; and six simulated CONTROLLER/ACTUATOR routes. The nine retained
MARKET/ROBOT/FINBOT routes require exact subject-bound `instance_checks`. These are described in
[package polish](PACKAGE_POLISH.md#selected-fresh-local-ledger-and-transaction-executions).
They add real bounded behavioral checks but do not discharge full-kind coverage,
external authority, real custody or settlement, physical effect, safety, runtime
correspondence, release or deployment. Missing selection or a missing exact
source-bound non-trigger remains `UNKNOWN`.
Newly registered kinds add unresolved applicability questions, including on the
two previously reviewed implementations; an old ledger or transaction review is
not a refutation of unrelated new roles.
Its source ownership is a proposed partition for review, not semantic proof.

The automatic Verifier-root path is narrower than that maintainer interface. It
replays only review and execution policies already selected by `objects.vstd`,
permits additive source ownership, refreshes hashes for the same evidence paths,
allows Python source-line relocation only when the same exposed surface multiset
remains, retains markup structural ordinals as identity, and refuses any semantic
surface removal, changed reason or declaration, decision change,
execution-selection change, or remaining review gap. Its external prepared and
committed receipts are recovery evidence only; the subsequent Tier-0 or package
gate must still establish its own result.

Reviewed answers have a second, narrower guard in the GRAPH payload. The selected
source-semantic profile maps each evidence path to its exact object,
classification and obligation questions. Python and stub paths bind a
location-free abstract syntax tree; other languages are byte-exact until an
extension supplies a selected parser. Automatic remigration may update a raw
hash after comments, formatting or line relocation preserve that identity, but a
semantic change or new/removed reviewed binding returns the exact
`MANIFEST_REFRESH_REVIEW_REQUIRED` entries. The explicit maintainer flag
`--select-source-semantic-profile` establishes or advances that review boundary;
ordinary polish cannot do so.

The current package GRAPH payload records the complete non-manifest source-census
coordinate. An exact match permits the refresh controller to validate the selected
manifest bridge without replaying all object reviews. A changed source coordinate
still invokes the full guarded migration and atomic publication path.

The external transaction journal contains the original byte backup, prepared
receipt, terminal commit or explicit abort/stale receipt, and a cooperative
exclusive lock. The candidate is fsynced before the final source/target recapture.
A competing target is preserved; post-replacement drift is labeled
`PUBLISHED_STALE` and never returned as `REMIGRATED`. Arbitrary writers that ignore
the lock remain outside the portable compare-and-swap guarantee.

The selected Verifier-self HARNESS launch profile follows the same rule at a more
specific boundary. Its manifest payload owns the reviewed launch identities,
necessity reasons, observation gaps, call AST digests and whole-source canonical AST
digests. Automatic remigration may change only byte hashes and diagnostic line
coordinates while those fields remain identical; semantic AST drift, added or
removed launch sites, and changed calls require explicit review.

## Contributor boundaries

`namespace_contracts.py` owns immutable kind definitions and inherited requirements.
`namespace_discovery.py` owns observations and separates declarations from hints.
`namespace_manifest.py` owns exact format and base-composition interpretation.
`namespace_classification.py` owns applicability and source-bound reason checks.
`namespace_consequences.py` owns typed consequential paths, bypass cuts, and the
exact catalog-compiled distinction between obligation demand and structural-role
evidence. `namespace_consequences.mjs` digest-rebinds that selected distinction,
then independently derives required kinds and witnesses; agreement therefore does
not independently establish the semantic type of a retention decision.
`namespace_admission.py` composes them, binds evidence, and preserves verdicts.
`namespace_reconcile.mjs` independently interprets selected portable inputs.

Keep comments next to the rule they explain: why it exists, what evidence it uses,
and what it cannot establish. A missing comment is not a failed financial proof;
a comment is never execution evidence. Tests must challenge removed labels,
unlisted methods, stale references, missing reasons, inheritance, parser ambiguity,
independent-interpreter disagreement, and accidental assurance promotion.
