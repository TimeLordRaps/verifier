# Selected ten-tier progression

Verifier Standard (VSTD); directed acyclic graph (DAG); JavaScript Object Notation
(JSON); Secure Hash Algorithm 256-bit (SHA-256); mebibyte (MiB).

`verifier-current-ten-tier-progression-1` separately selects this order: 1 Facets,
2 Dynamics, 3 Statics, 4 Closure, 5 Independence, 6 Security, 7 Privacy,
8 Consent, 9 Governance, 10 Corrigibility. Historical six-tier and current
nine-tier coordinates, certificates and dependency assessments retain their
original propositions. No historical rank is automatically converted. This
profile does not register kind-specific tier 10 objectives or migrate the
historical coordinate parser. Separately registered ten-tier native
`VERIFIER-6.1` is admitted only at rank 6 and `VERIFIER-10.1` only at rank 10;
these finite instances do not complete the required family or lower ranks.

Direct Python import: `verifier.runtime.tier_progression`.
`assess_tier_progression(selection_bytes, bundle_bytes=..., expected_policy_bytes=...,
artifact_files=..., expected_selection_digest=..., expected_mechanism_digest=...,
cancelled=False)` replays installed native certificates. The caller must select
the exact selection and gate implementation digests independently. Neither a
carried status nor a callback supplied by a producer can replace replay.

The canonical `verifier-ten-tier-progression-selection-1` has exactly
`schema_version`, `semantic_version`, `profile_id`, `subject`, `target_tier`,
`bundle_digest`, `policy_digest`, `artifact_files_digest`, `ranks`, `tiers`.
Semantic version is the profile identifier above. Subject contains `object_id`,
`object_kind`, `record_digest` matching one native policy-selected object.
At least one exact selected `required_roots` node must belong to that subject.
A subject that is merely a dependency of another object's selected roots cannot
claim root progression. A complete root set owned by other objects is FAIL;
an unavailable required root remains UNKNOWN and cannot unlock progression.
An empty or duplicate root selection is refused. This binds a finite root, not
the full application's operational inventory or authority.
Ranks contain unique `node_id`, integer `tier` pairs covering every exact native
node. Tiers contain all ten ranks exactly once, with `tier`, `census`,
`required_nodes`. Census is COMPLETE or UNKNOWN. Each node appears exactly once
among the required lists, at its selected rank. COMPLETE requires a nonempty
list. There is no unauthenticated inapplicability waiver or vacuous tier PASS.
Repeated labels for the same object/request/checker-policy instance are refused.

Bundle and policy retain [CERTIFICATE_DAG.md](CERTIFICATE_DAG.md) version 1
input contracts. Rank overlays add two constraints: a prerequisite cannot have
a greater rank than its dependent; all edges must be acyclic, including edges
within one rank. The native profile's exact dependency edges and subject,
proposition, scope, request, checker policy, facets and artifact bindings are
still checked. Validated rank, snapshot and namespace contradictions remain FAIL despite
explicit cancellation or missing external pins. Missing evidence and interrupted
replay remain UNKNOWN. Native assessment version 2 retains observations across
later interruption; observed FAIL cannot be erased by that interruption.

`verifier-ten-tier-progression-assessment-2` binds exact `selection_digest`,
supplied `expected_selection_digest` and `expected_mechanism_digest` (null when
absent), and the validated closed selected `subject` descriptor. Missing native
inputs, replay outage and report compaction retain these bindings. Version 1
reports remain historical under their original source; no implicit upgrade or
missing-binding wildcard is allowed. Version 2 contains native observations and
ten diagnostic tier rows. A direct tier can pass only when its selected census
is COMPLETE and every exact required instance is qualified native PASS.
Cumulative PASS requires that condition at every lower rank as well. Unresolved
native closure blockers or native UNKNOWN fence all progression clearance even
if every present node passed. `selected_depth` is the cleared consecutive finite
prefix; `selected_target_status` describes the selected target. Advancement to
the immediately following rank requires its entire cumulative prefix to pass.
An observed native refutation makes the assessment FAIL. Partial diagnostic
PASS rows do not authorize advancement.

Bounds: 1 MiB selection, 8 MiB per native record, 512 nodes, 4,096 edges,
1,024 artifact files, 64 MiB artifact content, 128 MiB referenced binding hash
work, and 8 MiB completed report. Native parsing/replay limits also apply.
Capacity exhaustion is UNKNOWN unless a refutation has already been observed.
Report compaction preserves FAIL and removes clearance. Artifact names and item
counts are checked before inventory hashing. Exact immutable bytes are captured;
locators, commands, credentials and carried code are never executed.

Family membership and requirement selection remain external responsibilities.
A COMPLETE label describes an externally selected finite list; hashes and labels
do not authenticate exhaustiveness or authority. No approved complete Verifier
application profile is supplied. `polished` is always false; full application
status and required operational certificate-instance census remain UNKNOWN.
Whole-tier conformance and inventory authority remain NOT_ESTABLISHED. Real
promotion evidence, independent checking and human acceptance remain separate.
The finite gate establishes no model correctness, overall safety or publication.
