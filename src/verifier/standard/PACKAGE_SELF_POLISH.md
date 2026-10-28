# Package GRAPH self-polish gate

This is the retained nine-tier ledger selected explicitly by `--package-graph`.
Ordinary `vstd polish 1`, `2` and `3` now use the target-tier root
[objects.vstd package evaluator](PACKAGE_POLISH.md).

Verifier Standard (VSTD) exposes the project-level wrapper as
`vstd polish 1 --package-graph --source-root PATH --json`. It first executes the
numeric Tier-1 self-polish mechanism on the `VERIFIER`, then represents the
selected VSTD package as one typed `GRAPH` with exactly one record for each of
the 26 retained `ObjectKind` wire kinds, including `EVENT`. This explicit
`--package-graph` compatibility ledger is not the ordinary root-manifest package
denominator: `vstd polish 1`, `2` and `3` assess the exact union of those 26 base
kinds and 12 installed additions, for 38 package kinds.

The report schema is
`verifier-package-graph-self-polish-assessment-1`. Secure Hash Algorithm
256-bit (SHA-256) digests bind the selected source, graph, mechanisms, retained
numeric report, installed route inventory, evidence certificates, and final
report. A package report is never release or deployment authority.

An exact candidate obligation-card bundle can be selected with
`--package-obligation-cards`, `--package-obligation-manifest`, and the required
`--package-obligation-manifest-digest` pin. An optional semantic reason ledger
uses `--package-obligation-reasons` together with the required
`--package-obligation-reasons-digest` pin. Partial selections fail closed.
Exact owner adoption can be selected separately with
`--package-owner-policy`, `--package-owner-policy-digest`,
`--package-owner-decisions`, and `--package-owner-decisions-digest`.

## Denominators

This retained compatibility gate keeps four denominators distinct; none is the
38-kind root-manifest package denominator:

1. 26 tier-zero representation/admission cells, one per object kind;
2. 234 core family cells, 26 kinds by the nine core tiers;
3. every installed core-route membership, currently 408; and
4. 26 separate corrigibility research cells plus one established-shape WIP
   extension selection.

Tier zero is not a tenth `MetaTier`. The package gate runs the installed
`vstd polish 0` repository-admission assessment and retains a strict summary of
its report, profile, manifest, mechanism, source census, nine obligation
outcomes, nine assessment reasons, and bounded finalization status. The exact
report digest and status are carried by the graph's `VERIFIER`, `EVENT`, and
`RECEIPT` records; `VERIFIER` also binds the profile digest.
A per-object Tier-zero cell may report `PASS`
only when that repository admission is finalized, the typed graph composes, and
the object's native facet checker discriminates its cases. Payload truth and
all Tier-1-plus semantic obligations remain `NOT_ESTABLISHED`.

## Native facet discrimination and route projection

For every package object, the gate builds both the generic object-facet request
and its kind-specific Tier-1 request. Each checker must independently reproduce
three cases: an exact positive (`PASS` or a preserved non-contradictory
`UNKNOWN`), malformed negative (`FAIL`), and absent evidence (`UNKNOWN`). The
current denominator is 52 objectives and 156 cases.

This establishes checker discrimination only. The exact native request identity
is projected into the installed route inventory by object kind, coordinate,
semantic version, proposition digest, checking mechanism, certificate schema,
and Tier 1. The package-specific projection selects 27 of 408 route memberships.
A separate installed-specimen replay executes all registered Tier-1 and Tier-2
native cases without promoting those specimens to package-instance evidence. All
408 obligation statuses remain `UNKNOWN` unless a contradiction is observed. A
selected checker `PASS` is never relabeled as semantic or normative closure. A
malformed negative case that returns either `PASS` or `UNKNOWN` is a definite
discrimination `FAIL`; a positive case may preserve non-contradictory
`UNKNOWN`. The route projection propagates selected checker `FAIL` and
`UNKNOWN` instead of reporting a stronger projection state. Its separate
`route_identity_projection_status` reports only exact request and specimen
identity matching, while `unknown_causes` names the retained obligation whose
outcome keeps the aggregate projection unresolved.

When a source root is selected, `full_native_candidate` additionally retains all
408 route specimens and their 1,224 cases. Its aggregate digest and status are
bound into the `VERIFIER`, `EVENT`, and `RECEIPT` records. The first 82 routes
are installed Tier-1 and Tier-2 specimens; 326 Tier-3-through-9 routes retain
`PREPARED_NOT_INSTALLED`. Each prepared checker must originate in the loaded
Verifier distribution and exactly match its selected repository bytes; physical
checkout and installation paths need not be identical. Candidate replay does
not install those extensions or establish that the package is a passing
instance of their propositions.

## Candidate obligation ledger

The optional candidate selector reads exactly one JavaScript Object Notation
(JSON) card for every admitted
kind, rejects duplicate JSON keys and unexpected card files, verifies every
card byte digest against the selected manifest, and joins every proposed row to
an installed route by object kind, coordinate, and tier. A valid current bundle
therefore binds 26 cards and 408 unique objective identities. The selector
retains candidate revision classes, presence or type conditions, mechanism
assessments, reason verdicts, failed-test labels, served facets, and unresolved
owner-question digests.

Selection `PASS` is mechanical only. Candidate content remains `INFERRED`. A
separately pinned reason ledger must bind every route claim, facet, evidence
description, semantic version, and current checker-module digest before semantic
identity is `PASS`; that still grants no normative status. Owner adoption and
normative closure remain `NOT_ESTABLISHED`; every joined
obligation remains `UNKNOWN`. A missing selection is `NOT_SELECTED` and a
malformed, hash-mismatched, incomplete, duplicated, or inventory-divergent
selection is `FAIL`. No workstation path is emitted in the report.

Owner adoption is a separate configured-key admission. The signed statement
must bind the candidate selection, source coordinate, and all 110 exact decision
subjects under independently digest-pinned policy bytes. Without those inputs,
adoption remains `NOT_SELECTED` and no owner-decision references are projected.
Signature `PASS` authenticates only that configured-key statement; it does not
establish personhood, legal authority, candidate truth, normative closure,
corrigibility, release, or deployment authority. The detailed contract is in
`PACKAGE_OWNER_DECISIONS.md`.

## Numeric VERIFIER retention and source binding

The numeric report is retained only through the strict Tier-1 validator. A
rejected report digest is not written into the graph. Non-PASS reports do not
export their claimed subject, represented tiers, or source-binding status.

When `--source-root` is selected, the wrapper recaptures the whole source before
and after its source-dependent package reads with the same capture mechanism and
compares both observations with the numeric report coordinate. The report keeps
the more severe observed state, so a later mismatch or outage cannot be erased
by an earlier match. Equality is a source-binding result, not independent
evidence, and does not establish package completeness. An
unavailable wrapper preserves a numeric `UNKNOWN` as package `UNKNOWN` and
emits the package schema rather than silently substituting a numeric-schema
failure. If the package mechanism bytes themselves are unavailable, that bounded
fallback emits a null mechanism digest instead of fabricating one.

Every graph record commits to the opening captured source-evidence summary when
available. The package-gate mechanism digest embedded in the `VERIFIER` record
is recaptured before the closing source observation; a changed digest is a
definite `FAIL` and an unavailable recapture remains `UNKNOWN`. The closing
source recapture fences subsequent drift. The `EVENT` and `RECEIPT` records
bind both the retained numeric run and the Tier-zero repository-admission run;
a rejected, unavailable, or unselected run keeps that distinct lifecycle
state. The `VERIFIER` record binds the numeric mechanism, Tier-zero report and
profile, package gate, and candidate selector. Canonical records are
serialized, reconstructed, and composition-checked after the round trip.

## Corrigibility boundary

Per-kind records use
`verifier-package-corrigibility-cell-selection-1` and remain `WIP`, `NOT_RUN`,
`NOT_ESTABLISHED`, and `UNKNOWN`. Their aggregate digest is carried by the
existing `verifier-corrigibility-extension-selection-1` shape with
`declared_status: WIP`. The extension is separate from the nine core tiers and
cannot change any core result until a native all-kind mechanism and its
qualification contract are established.

The gate binds the exact research-boundary document, the local
`verifier.corrigibility` module set, and the finite `VERIFIER-10.1` replacement
mechanism as research inputs. None is relabeled as an all-kind checker or
extension credit.

## Promotion boundary

Tier-zero repository admission, graph composition, numeric Tier-1 `PASS`,
native checker discrimination, installed specimen replay, candidate selection,
route projection, local tests, and source equality are necessary bounded
results; none closes the 234 core family cells or the corrigibility extension.
The project remains `UNKNOWN` while any required closure is not established.
`FAIL` propagates from a numeric verifier failure, graph contradiction,
tier-zero repository or object-admission failure, native checker-discrimination failure,
installed-specimen replay failure, candidate-selection failure, route-identity
projection failure, owner-admission failure, or source-recapture mismatch. `polished` and
`release_authorized` remain false until the complete project gate is
implemented and independently validated.

## Independent retained-report recheck

`verifier.runtime.package_self_polish_recheck` validates retained report bytes
without importing the package-report producer. It rejects duplicate JSON keys,
non-finite values, oversized inputs, internal digest substitution, typed graph
or denominator drift, cross-section binding differences, inconsistent replay
counts, non-monotone route-to-cell results, and missing required blockers. It
also reconstructs all 26 graph records and the installed 234-cell, 408-route
denominator from current mechanisms.

For current-mechanism reports, it reruns the selected generic and typed facet
cases and rebuilds and replays every installed Tier-1 and Tier-2 specimen. A
complete retained/reproduced mismatch is a recheck failure. A mismatch involving
an explicit resource-unavailable case remains recheck `UNKNOWN`. Candidate-card
and native-replay mechanism paths retain canonical `src/verifier/...`
coordinates. A checkout selection must resolve strictly below its own `src`
directory; an installed recheck selects only the distribution that supplied the
running module. Byte equality, not coincidental physical-path equality, binds a
selected checkout to the loaded distribution, and neither mode falls back to
the other when its selected file is missing. Those bindings do not establish
candidate-card semantics, source truth, owner real-world authority, or normative family
closure are not independently established by this retained-report recheck. The
retained numeric Tier-1 report, configured-key owner signature, source
observations, the bound Tier-zero report, and candidate card, manifest, and
reason-ledger byte bindings are shape-, digest-, and pointer-checked; the
rechecker does not independently reread, rerun, or authenticate them. The
Tier-zero report itself includes the Python/Node agreement produced by
`vstd polish 0`; the package rechecker validates its binding rather than
pretending to be a third independent parser. Report and byte digests select
content but do not authenticate its author.

The full native candidate receives a separate structural check of route
identities, case outcomes, aggregate counts, digests, and installation status.
The package rechecker does not independently replay its prepared
Tier-3-through-9 specimens. This limitation is carried in the recheck result.

The output schema is
`verifier-package-graph-self-polish-recheck-1`. Recheck `PASS` means only that
the retained report is internally consistent under the current installed
mechanisms. The separate `rechecked_project_status` remains `FAIL` or `UNKNOWN`;
recheck `PASS` can never be read as package polish. A report from an older
package mechanism yields recheck `UNKNOWN`, not a retroactive semantic `FAIL`.
The public route is
`vstd polish recheck-package REPORT --report-digest sha256:...`
`--report-bytes-digest sha256:... --json`. The semantic digest and exact retained
byte digest are separate required selections.
Exit code `0` means that this retained-report integrity recheck returned `PASS`;
it does not mean the retained project status passed, and it grants no package
polish, release, or deployment authority.
