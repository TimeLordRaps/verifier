# Core application authority binding

Status: private additive contract candidate. It defines exact denominator binding
and no release authority.

The mechanism compares one existing
`verifier-core-application-required-instances-1` record with a versioned profile
supplied through a native authenticated-host selection. Candidate bytes never
select the profile, expected digest, consumer coordinate, installed mechanisms,
union authority, contribution snapshot, or qualified scope-admission receipt. The
three raw host-selected records must be immutable bytes within the 16 MiB per-record
ceiling before any digest or decoder work is performed.

Before member or instance binding, the mechanism executes the selected installed
union validator on the exact host-selected
`verifier-core-obligation-union-authority-candidate-1` bytes and the exact canonical
contribution snapshot. The conserved report must bind the same authority and
contribution digests and report `authority_binding`, `source_coordinate_binding`,
`dependency_binding`, `candidate_coverage`, and `structural_union` as matched/PASS,
with no issues. `semantic_completeness` remains UNKNOWN and `release_admissible`
remains false. A selected mechanism digest or selected input hash cannot replace
this native control flow.

The versioned host profile binds the exact consumer source coordinate, installed
core consumer, application compiler and union-validator mechanisms, the complete
234 family applicability selection, exact union members and their source/claim
bindings, operational certificate instances, child requirements, interaction
requirements, compiler manifest and exact
`ADMIT_APPLICATION_REQUIREMENT_SCOPE` subject. Carried collections are compared as
sets where the existing core and union formats are order-insensitive. Omissions,
extras, duplicate identities, changed source/mechanism/subject bindings and
unauthorized inapplicability fail.

The scope-admission subject is reconstructed from the compiler manifest's exact
input-digest map, installed compiler mechanism, full-application scope and verified
closure certificate. The closure certificate binds the same inputs and mechanism,
has an internally reproduced digest and retains completeness as `UNKNOWN`. Equality
among a caller-supplied subject and caller-supplied digest pins cannot establish this
binding. The installed union validator is imported from the `verifier` package; no
private absolute-path fallback participates in an installed assessment.

Current mode is `NO_INAPPLICABILITY`. Every member is REQUIRED or UNKNOWN. The
installed compiler subject retains `admitted_inapplicability: []`. Opaque selected
receipt bytes grant no credit. The versioned qualified-authority replayer requires
an independently host-selected receipt, policy, policy and receipt digests, installed
mechanism digest, operation, operation revision, instruction revision, context
revision, subject, evaluation time and minimum signed-status sequence. It verifies
an Edwards-curve Digital Signature Algorithm with a 255-bit field (Ed25519)
configured-key quorum and a separate fresh signed status key. Carried,
cancelled, stale or incomplete evidence stays UNKNOWN. A changed binding, signature,
role or authenticated denial fails.

Every bounded approval and status envelope's closed shape, selected role,
key-to-actor relation, self-approval exclusion, duplicate identity, body/status
binding and claimed time fields are checked before optional signature work.
Every approval must claim `issued_at < expires_at`, and status must claim
`observed_at < expires_at`; empty and inverted windows are independently
refutable before optional crypto work, including in later approvals.
An independently refutable submitted claim remains FAIL when that backend is
unavailable. A consistent claim still requires successful authentication for
authority, quorum, revocation or decision facts; genuine backend absence remains
UNKNOWN and cannot grant PASS.

`ADMIT_APPLICATION_REQUIREMENT_SCOPE` and
`ESTABLISH_APPLICATION_SEMANTIC_COMPLETENESS` have distinct installed mechanism
domains and receipt selections. The semantic subject binds the exact authority
profile, requirements, union authority and contributions, compiler manifest,
scope-admission subject and receipt, consumer source coordinate and all three
installed application/compiler/union mechanisms. A scope receipt cannot be cast as
a semantic-completeness receipt. Structural union success remains insufficient.
Configured-key PASS establishes only the selected statement under those roots; it
does not prove personhood, legal authority, ontology completeness, human acceptance,
polish or release.

Candidate child or interaction PASS is unsupported without its native rechecker and
fails. Known child or interaction FAIL makes the assessment FAIL. Missing or
undecided evidence stays UNKNOWN. An exact structural binding can set
`binding_status=PASS`. Independently selected qualified receipts can set
`authority_status=PASS` and `semantic_completeness=PASS`; unresolved child or
interaction evidence still keeps the full application UNKNOWN. Polish, human
acceptance and release remain false.

The consumer mechanism digest must include the authority module and this
specification, in addition to its existing direct dependencies. Installed mechanism
digests are computed from installed source by the integration call path and compared
with host-selected pins. Application metadata cannot supply an observed mechanism.
