# Dangerous-pathway security interoperability

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256); command-line interface (CLI); application
programming interface (API); identifier (ID).

**Status:** experimental version 2 mechanical interoperability, with version 1
retained as a legacy unqualified record. This mechanism
does not select a ClaimGarden policy, establish exhaustive safety, grant
publication authority, publish an object, or implement hosted moderation.

The design input is the ClaimGarden document whose exact retained digest was
`sha256:91cfed1c45a9fda70bc9e9d8cfa19f76afe6396496652f13593bb3e89df9acda`.
That source declares itself `DESIGN_ONLY / NOT_IMPLEMENTED /
NOT_A_SECURITY_CLEARANCE`. The digest is interoperability provenance, not
implementation authority, adoption evidence, or permission to distribute.

## Separate decisions

Computational polish, dangerous-pathway security, and publication authority are
separate. A selected VSTD proposition can replay `PASS` while a dangerous
capability remains present. A security assessment can mechanically reproduce
without giving any person or organization authority to publish. Every native
result therefore fixes `publication_authority=NOT_ESTABLISHED`.

Mechanical `status` has values `PASS`, `FAIL`, or `UNKNOWN`. It reports whether
the exact selected record reproduced, contradicted its contract, or remained
unavailable. `security_outcome` separately has `ESTABLISHED`, `FAIL`, `UNKNOWN`,
or `NOT_ESTABLISHED`. A mechanically valid observation of a present dangerous
pathway is `status=PASS` and `security_outcome=FAIL`.

For risk-bearing objects, the aggregate retains exactly five ordinary-polish
rows (`FACETS` through `INDEPENDENCE`, tiers 1–5) and separately derives a tier
9 `SECURITY` status. All five ordinary rows are necessary for `R2`; they cannot
substitute for the pathway, counterexample, capability, review, invalidator, or
composition evidence that derives the Security-9 result.

## Object and risk scope

The request admits every current VSTD object kind. Every simulation (`SIM`)
enters moderation as `R2_PENDING`; an `R2` bounded interface still requires the
full independent-refutation gate below, while a present dangerous pathway makes
the simulation `R3`. Model (`MODEL`), agent (`AGENT`), harness (`HARNESS`), bot
(`BOT`), data (`DATA`), and other kinds likewise depend on exact capability,
affordance, operating envelope, distribution surface, and composition. Object
kind alone never clears an artifact.

The assessment binds an observed capability inventory,
observer-mechanism/certificate/replay digests, generalizable-tooling state, and
a risk floor. `SIM` and `MODEL` use the same capability rule: observed
generalizable tooling requires at least `R2`, and no aggregate may fall below
the observed risk floor.

Risk assurance uses the distinct names `SEC0_UNASSESSED`,
`SEC1_INVENTORY_BOUND`, `SEC2_PATHWAYS_REPLAYED`,
`SEC3_INDEPENDENTLY_REFUTED`, and `SEC4_CONTINUOUSLY_GOVERNED`. These are not
VSTD meta-tier numbers, Security-9 credit, the experimental ten-tier Security-6
mechanism, or containment tiers.

## Request

`verifier-dangerous-pathway-request-1` selects one catalog pathway. It binds:

- exact artifact and separately identified derived distribution surface;
- source coordinate and dependency inventory;
- object kind;
- host risk policy, threat-catalog digest and version, and exact pathway-search
  scope digest;
- operating envelope and capability inventory;
- pathway identifier, catalog-entry digest, and severity;
- sorted required checks with purpose, mechanism, request, and policy digests;
- confidential-evidence markers;
- reviewer and invalidator policies; and
- finite check, review, and invalidator limits.

The request binds the installed mechanism digest and its own canonical digest.
It contains no executable, file path, locator, callback, command, or dynamic
import. A producer cannot select code by field resemblance.

## Pathway certificate

`verifier-dangerous-pathway-certificate-1` retains the complete request and one
result for every selected check. Result rows bind certificate and replay
digests; they never cause the native mechanism to execute producer-controlled
code. Exact canonical replay validates the request, selection/result equality,
all derived outcomes, the claim boundary, and the certificate digest.

Those certificate and replay digests are opaque version-1 record fields. No
fixed installed semantic replayer validates the selected mechanisms they name.
Consequently the carried certificate outcome is exposed by the public replay
surface only as `recorded_security_outcome`; it is never an effective clearance.
Even a caller-coherent record containing arbitrary digests, `PASS` rows, and a
fresh outer hash returns effective `security_outcome=NOT_ESTABLISHED` (or
`UNKNOWN` when that is the recorded outcome), `security_eligibility=DENY`, and
decision exit 2. A future positive result requires a fixed installed replayer
that derives each selected check result from canonical evidence bytes and its
mechanism logic rather than trusting these fields.

Applicability is `APPLICABLE`, `PROVED_NOT_APPLICABLE`, or `UNKNOWN`.
`PROVED_NOT_APPLICABLE` requires a retained applicability-evidence digest and a
selected `APPLICABILITY` check that reports `PASS`. Publisher assertion or an
empty record cannot establish it.

Pathway verdicts are:

- `REFUTED_WITHIN_ENVELOPE`: selected refutation and adversarial
  counterexample-search checks pass for the exact envelope;
- `CAPABILITY_REMOVED`: a selected removal check passes and the derived surface
  digest differs from the retained artifact digest;
- `CONTAINED_NOT_REFUTED`: selected containment and mitigation records pass but
  do not establish unreachability;
- `PRESENT`: a selected trigger check passes and binds a triggering-witness
  digest; and
- `UNKNOWN`: the selected proposition was not established.

Confidential digest-only evidence cannot report a mechanical `PASS` in version
1 because no confidential proof verifier is installed. Missing checks,
unsupported check results, active invalidators, unknown applicability, and
unresolved verdicts remain `UNKNOWN`. Known selection, field, digest, or result
contradictions are `FAIL`.

`PRESENT` means the checker successfully established a selected harmful path;
the certificate is mechanically `PASS` but its security outcome is `FAIL`.
`CONTAINED_NOT_REFUTED` remains `UNKNOWN` for security clearance. Only a
mechanically passing refutation, separately derived capability removal, or
mechanically proved inapplicability can yield `security_outcome=ESTABLISHED` for
that selected pathway.

Each certificate also carries a separate residual-risk status. Residual
`UNKNOWN` or `NOT_ESTABLISHED` preserves mechanical replay `PASS` when the
record reproduces, but keeps security `UNKNOWN`; residual `FAIL` makes the
security outcome `FAIL`.

## Aggregate assessment v2

`claim-garden-dangerous-pathway-assessment-2` is the current assessment
contract. Version 1 remains readable so retained evidence does not disappear,
but its caller-declared four-field predecessor is not sufficient for promotion,
its replay result is always `security_eligibility=DENY` with reason
`R2_PREDECESSOR_REPLAY_NOT_ESTABLISHED`, and it is never auto-upgraded to
version 2. Its recorded historical outcome remains observable separately; it is
not current security qualification.

The exported `aggregate_dangerous_pathway_assessment` compatibility boundary
therefore returns the replayed `LEGACY_UNQUALIFIED` decision directly, with
effective security `NOT_ESTABLISHED`, eligibility `DENY`, and reason
`R2_PREDECESSOR_REPLAY_NOT_ESTABLISHED`; it cannot mint a fresh positive v1
security result. Exact retained v1 records remain readable by the replay API.

Version 2 embeds the complete canonical prior version-2 assessment. The native
reader recursively replays that assessment, including its derived outcomes and
digest, instead of trusting a predecessor digest or risk string. A configurable
historical timestamp is not an admitted authority input. The record therefore
fixes `catalog_authority=UNKNOWN`, `assessment_time_authority=UNKNOWN`,
`reviewer_authority=NOT_ESTABLISHED`, and
`publication_authority=NOT_ESTABLISHED`.

Version 2 does not treat digest-shaped strings, producer-authored `PASS`, or a
self-hash of either as eligibility evidence. It embeds a sorted
`evidence_artifact_manifest` of immutable references only. Each reference binds
one derived contributor identifier and kind, an artifact identifier of the
form `urn:sha256:<hex>`, the matching digest, and the single fixed replayer ID
required by the installed mechanism. Exact canonical artifact bytes are
separate inputs to construction or replay; they are never reconstructed from
the assessment row and never replaced by an assessment-local receipt.

The derived contributor inventory covers source and package inventories; each
pathway's applicability, verdict, selected check results, counterexample search,
and residual risk; each ordinary tier; reviewer identity, conflict check, and
review result; capability, catalog, and operating envelope; each interaction
and the complete composition; and each invalidator plus invalidator coverage.
The reader verifies immutable IDs and digests, resolves exact bytes within
finite limits, checks assessment-bound artifacts byte-for-byte, and dispatches
only by the fixed installed kind-to-replayer table. A manifest cannot select a
path, callback, import, command, or substitute replayer.

This package currently installs no semantic replayer sufficient to establish
any of those eligibility contributors. Therefore even a complete manifest with
digest-correct canonical bytes replays `UNKNOWN`; producer-authored statuses in
those bytes are ignored as oracles. Missing bytes, missing contributors, absent
replayers, or otherwise unreplayed artifacts keep security `UNKNOWN`,
eligibility `DENY`, tier status `UNKNOWN`, and release scope `DENY`. A wrong
digest, substituted bytes, unresolved contributor, or substituted replayer is
a contradiction and is rejected. No legitimate positive v2 eligibility path
exists until real per-kind replay mechanisms are installed and independently
qualified.

The record also binds the installed mechanism digest over the implementation,
this standard text, and the request, certificate, legacy-assessment, and v2
assessment schemas, plus explicit source and package inventory digests. Its
derived scope binds those digests and every
explicit subject, source coordinate, dependency, capability, policy, catalog,
and topology pin; there are no producer-chosen defaults. The derived
The schema reserves
`ELIGIBLE_FOR_SEPARATE_PUBLICATION_AUTHORIZATION` for a future mechanism that
actually installs and qualifies every required semantic replayer. This version
always derives `security_eligibility=DENY`; an `R2` label and digest-correct
artifacts cannot change that. Even a future eligibility state would only be an
input to a separate host decision: it could not change
`publication_authority` from `NOT_ESTABLISHED` or select host policy.

The `assessment_scope_digest` is derived by the installed mechanism from the
subject identity and source coordinate, dependency and capability inventories,
namespace and policies, the exact catalog manifest, and component/interaction
topology. It excludes outcomes, reviews, evidence references, invalidators, and
risk labels. A host cannot declare this digest. Any change to that static scope
restarts the state machine at `R2_PENDING` with release scope `DENY`.

The first assessment of a subject is `R2_PENDING` and `DENY`. Within an
unchanged scope the only promotions are `R2_PENDING` to `R2` or `R3`, `R2` to
`R2` or `R3`, and `R3` to `R3`; a pending assessment may remain pending. Direct
initial `R2`/`R3`, same-scope downgrade, and scope-substituted promotion are
rejected. A present pathway may be retained in the initial pending quarantine,
then promotes to `R3`; it cannot bypass the initial state.

An initial assessment has null `predecessor_assessment_digest` and
`predecessor_replay_digest`. Every successor derives both: the exact embedded
assessment digest and a replay digest binding that assessment's canonical byte
digest to `replay_status=REPRODUCED`. They are checked rather than accepted as
host assertions. This proves bounded native reproduction of the embedded bytes,
not that a host selected the right predecessor or that the assessment is fresh.

Version 2 embeds the exact sorted catalog manifest as pathway identifier,
entry digest, and severity, and derives `threat_catalog_digest` from that
manifest. Every `HIGH` and `CRITICAL` entry requires exactly one certificate
whose identifier, digest, severity, catalog, scope, subject, and source bindings
match. Omitted high-severity entries, extra certificates, severity substitution,
duplicate identifiers/digests, and manifest substitution are contradictions.
LOW and MEDIUM entries may lack pathway certificates, but remain visible in the
exact catalog and coverage digest; this is not an absence or safety claim.

The remaining v2 mechanics retain the bounded gates below from version 1.

### Legacy version 1

`claim-garden-dangerous-pathway-assessment-1` is a host-selected aggregate. It
binds artifact, derived surface, source, dependencies, namespace, polish
receipt, policy, catalog, envelope, capability inventory, the submitted selected
catalog-entry list, pathway certificates, component risks, interaction tests,
predecessor assessment, reviewers, and invalidators.

The required `r2_evidence` record binds five independent gates:

- capability observation and generalizable-tooling risk floor;
- exact pinned catalog version, search scope, selected-entry count and digest,
  with the constant scope claim `PINNED_CATALOG_ONLY`;
- operating-envelope replay;
- invalidator-policy and exact invalidator-inventory coverage; and
- exact component and interaction-inventory coverage.

Every gate must report `PASS` for `R2`, but that string is only a necessary
input condition. The corresponding exact external artifact must also replay
`PASS` through its fixed installed semantic mechanism. `UNKNOWN`,
`NOT_ESTABLISHED`, `FAIL`, missing bytes, or an absent replayer blocks security
eligibility; it is never repaired by an ordinary-polish receipt.

The catalog-entry list and sorted pathway-certificate catalog digests must be
identical, and the coverage record binds that list, its count, the catalog
digest/version, and the search scope. This establishes completeness only
relative to those exact pinned host inputs. It never establishes the absence of
unknown, future, out-of-scope, or newly discovered pathways.

Composition cannot lower the maximum selected component risk. Two or more
components require an explicit higher-order interaction-amplification record
whose sorted component list covers the complete composition; pairwise-only
records do not clear a larger composition. A missing or unknown full-composition
result keeps mechanical status `UNKNOWN`; an observed amplification failure
requires `R3`, security `FAIL`, and release scope `DENY`.

A `PRESENT` pathway also requires `R3`, security `FAIL`, and `DENY`. An `R3`
predecessor cannot be downgraded when either the artifact or derived-surface
digest is unchanged. Removing an affordance therefore produces a new artifact
or surface digest, capability inventory, verification coordinate, and
assessment rather than rewriting the old classification.

`R2` requires all selected pathways to be mechanically passing and either
refuted, capability-removed, or proved not applicable. Assurance must be
`SEC3_INDEPENDENTLY_REFUTED` or `SEC4_CONTINUOUSLY_GOVERNED`, with at least two
distinct passing reviewer identifiers and two distinct review mechanisms whose
conflict checks pass. All five ordinary-polish tiers, all exact `r2_evidence`
gates, and residual-risk `PASS` are also required. Every contributor additionally
requires an exact artifact and installed native replay `PASS`. These rows are
bounded host inputs and never prove a real person's identity or independence;
the current absence of the required semantic replayers keeps the result
`UNKNOWN`/`DENY`.

`R2_PENDING` has security outcome `UNKNOWN` and always has maximum release scope
`DENY`. `R3` always has `DENY`, at every assurance level and even when no
triggering witness has yet been established.
Irrespective of risk, assurance, or release-scope ceiling,
`publication_authority` remains `NOT_ESTABLISHED`.

Invalidators name exact digest-bound rules and have `ACTIVE`, `CLEARED`, or
`UNKNOWN` status. Any non-cleared invalidator makes the assessment mechanical
status `UNKNOWN`. Catalog, policy, artifact, dependency, envelope, affordance,
review, incident, or counterexample changes require a new assessment. Revoking
a current release cannot recall already-downloaded bytes.

Payment or customer priority may affect private service scheduling only. It is
not an admitted assessment field, cannot select a weaker catalog, waive any
gate, create reviewer independence, convert `UNKNOWN`, lower the capability
risk floor, expand release scope, or confer publication authority.

## Interfaces and exits

The direct experimental Python interface is:

- `dangerous_pathway_request`;
- `build_dangerous_pathway_certificate`;
- `recheck_dangerous_pathway_certificate`;
- `aggregate_dangerous_pathway_assessment`;
- `aggregate_dangerous_pathway_assessment_v2`;
- `recheck_dangerous_pathway_assessment`; and
- `recheck_dangerous_pathway_assessment_v2`;
- `dangerous_pathway_catalog`.

`verifier.runtime.security_cli` supplies read-only `catalog`, `pathway-check`,
and `aggregate` parser/handler helpers. They become public only after the shared
CLI explicitly registers and dispatches them. For decision commands, exit 0
requires both mechanical `PASS` and security `ESTABLISHED`; exit 1 means malformed
or contradictory mechanics, or security `FAIL`; exit 2 means security `UNKNOWN`
or `NOT_ESTABLISHED`. Informational `catalog` is the sole non-decision exception:
exit 0 reports successful local metadata retrieval and establishes no security
outcome. No command performs transport or publication.

The aggregate command dispatches by explicit assessment schema. A version-1
aggregate can reproduce its recorded bytes but returns effective security
`NOT_ESTABLISHED`, eligibility `DENY`, and decision exit 2. A future mechanism
revision may admit the separate-authorization eligibility state only after
every required installed semantic replayer returns `PASS`; this version has no
such replayers and always keeps v2 `UNKNOWN`/`DENY`. No legacy record is inferred
or converted into v2.

Likewise, `pathway-check` can reproduce version-1 certificate structure but has
no installed selected-check semantic replayer. It reports the carried value only
as `recorded_security_outcome`, returns effective `NOT_ESTABLISHED` or `UNKNOWN`,
denies eligibility, and exits 2. Structural consistency and rehashing of opaque
caller-authored digests do not change that decision.

All readers reject duplicate or unknown fields, noncanonical JSON, foreign
containers, excessive depth/count/bytes, unsupported integer sizes, changed
digests, and substituted bindings. Capacity exhaustion is unavailable and
therefore `UNKNOWN`, not a fabricated refutation or success.

## Remaining authority

This repository provides no host threat-catalog authority, capability observer,
reviewer identity service, conflict-of-interest authority, confidential proof
protocol, hosted invalidator monitor, distribution control, human acceptance,
or publication decision. A host must implement and independently qualify those
surfaces before making any claim stronger than bounded mechanical replay.
