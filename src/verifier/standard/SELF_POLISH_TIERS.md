# Numeric Verifier self-polish tiers

Verifier Standard (VSTD) exposes numeric self-polish as a conservative adapter
over installed mechanisms. JavaScript Object Notation (JSON) output is stable;
Secure Hash Algorithm 256-bit (SHA-256) digests bind retained inputs. The
command-line interface (CLI) spellings are `vstd polish 1` and
`vstd polish 2`.

The numeric result is not a scalar assurance score or historical
numbered-profile conformance. It is intended as a complete-tier gate over the
first two ranks of the current nine-core-tier inventory, but the installed
route inventory is only one required bounded subset of that gate:

1. `FACETS` covers every installed tier-1 family cell and membership.
2. `DYNAMICS` covers every installed tier-2 family cell and membership, after
   a mechanically established whole-tier tier-1 `PASS` at the identical source
   and installed denominator.

The adapter derives rather than hard-codes its denominator. The current
installed inventory has 234 family cells and 408 route memberships across all
nine tiers. Tier 1 has 26 cells and 45 memberships; tier 2 has 26 cells and 37
memberships. These totals and the exact membership identities appear in
`installed_denominators.complete_tiers`. A changed installed inventory changes
the required ledger and its digest. The 45 Tier-1 memberships repeat only 15
unique checking mechanisms across object kinds. They do not enumerate the
complete repository, package, public application programming interface (API),
CLI, schema, dispatch, or checking-mechanism estate.

The structural denominator is also different from the Tier-1 route
denominator. It currently contains 52 memberships from 27 definitions. The
two sets share 27 `(object_kind, coordinate)` identities, with 25
structural-only and 18 route-only identities. Matching proposition digests on
the shared identities is a consistency check, not an authenticated complete
crosswalk. The report therefore carries separate fields for installed-route
normative closure, objective-inventory closure, structural-route crosswalk
closure, repository/package estate closure, and post-replay full-source
recapture.

## Candidate-estate census input

Tier 1 can independently recompute Supervisor D's frozen
`verifier-self-polish-candidate-estate-1` census through
`verifier.runtime.self_polish_estate`. The caller supplies an expected
repository, revision, and estate digest. The adapter reruns the census against
`--source-root`, requires its revision to equal the core self-polish source
HEAD, recomputes the estate digest, checks every required category, checks the
pre/post tracked-byte census, and checks the exact 52-to-45 structural/route
counts. A digest-shaped caller value without the fresh recomputation is not
accepted.

The corresponding CLI inputs are `--candidate-estate-repository`,
`--candidate-estate-revision`, `--candidate-estate-digest`, and optionally
`--candidate-estate-applicability-ledger` with
`--candidate-estate-applicability-ledger-digest`. The applicability ledger is
validated afresh against the recomputed exact candidate identifier set.
Missing, duplicated, stale, substituted, mutated, or untracked inputs fail
closed under the estate mechanism's fixed refusal codes.

The census and applicability ledger are also the exact subject of an
independently selected estate-authority replay. The authority selection is
supplied through the `--candidate-estate-authority-policy`, policy-digest,
receipt, receipt-digest, mechanism-digest, operation-revision-digest,
instruction-revision-digest, context-revision-digest, subject-digest,
evaluation-time, and minimum-status-sequence options. The adapter accepts
either the complete selection or none of it. The receipt is replayed with the
installed configured-key mechanism against the freshly constructed estate
subject; carried authority `PASS` text is never trusted.

Per-candidate semantic evidence is selected separately through
`--candidate-estate-evidence-manifest`,
`--candidate-estate-evidence-manifest-digest`,
`--candidate-estate-evidence-mechanism-digest`, and repeatable
`--candidate-estate-evidence-selection` inputs. The manifest, digest, and
mechanism pin are atomic. Each selection option names one canonical JSON file
with exactly these fields:

```json
{
  "candidate_id": "the exact candidate identifier",
  "policy": {"configured-key policy": "complete canonical object"},
  "expected_policy_digest": "sha256:...",
  "receipt": {"configured-key receipt": "complete canonical object"},
  "expected_receipt_digest": "sha256:...",
  "expected_mechanism_digest": "sha256:...",
  "expected_operation_revision_digest": "sha256:...",
  "expected_instruction_revision_digest": "sha256:...",
  "expected_context_revision_digest": "sha256:...",
  "expected_subject_digest": "sha256:...",
  "evaluation_time": 0,
  "minimum_status_sequence": 0
}
```

Duplicate candidate selections and selections outside the fresh candidate set
fail closed. A partial selection is allowed only as an unresolved observation:
every missing candidate receipt remains `UNKNOWN`. Bounded estate-evidence
`PASS` requires the exact census and applicability ledger, a current passing
estate-authority replay, the exact complete manifest, and a current
configured-key replay for every candidate. Malformed, substituted, stale,
wrong-subject, or revoked evidence is `FAIL`.

A matching census proves bounded mechanical enumeration and tracked-byte
integrity only. Its own `semantic_applicability_status` and
`full_estate_closure` are `NOT_ESTABLISHED`. Caller-authored applicability,
authority, evidence `PASS` values, and SHA-256-shaped digests remain
unauthenticated declarations; the adapter exposes their count but grants no
semantic, authority, or replay credit. Independent applicability authority and
per-obligation evidence replay are still required, so this input never by
itself promotes Tier 1.

## Narrow receipt boundary

The retained `CORE-SELF-POLISH-1` route replays two concrete instances. The
numeric report records them as `NARROW_EVIDENCE_SUBSET`, with
`establishes_complete_tier: false`. That receipt, a selected VERIFIER row, or
any other subset can never clear either complete-tier command.

The complete-tier ledger input uses schema
`verifier-self-polish-complete-tier-ledger-1`. It binds the exact source,
installed 234-cell and 408-membership totals, selected tier cell and membership
totals, every installed membership identity, and per-row applicability,
authority, observation, native-assessment, and provider-review declarations.
Each digest-bound row also carries a stable obligation identifier; definition
source and version; implementation files, symbols, and checking mechanism;
evidence sources, freshness, and source binding; dependencies and
prerequisites; platform and binding applicability; expected positive,
negative, and `UNKNOWN` behavior; supervisor and owner; separate Claude and
Antigravity state and receipt fields; implementation status; focused
validation; independent replay; final disposition; and any justified
exclusion with its authority digest. Missing audit fields are a malformed
ledger, while populated fields remain descriptions until their evidence is
replayed.
The complete self-representation input uses schema
`verifier-self-polish-complete-representation-1`; it binds the same source and
inventory, cumulative represented tiers, the ledger digest, any prior tier
report, unobserved fields, and representation evidence. When candidate-estate
evidence is supplied, `estate_evidence_result_digest` is mandatory and must
equal the freshly replayed estate-evidence result digest. Omitting or replacing
that binding cannot splice an estate result into a different representation.

The CLI accepts these inputs through `--complete-tier-ledger`,
`--complete-tier-ledger-digest`, `--complete-self-representation`, and
`--complete-self-representation-digest`. Tier 1 additionally requires an
external canonical replay manifest and independent pins through
`--complete-tier-evidence-manifest`,
`--complete-tier-evidence-manifest-digest`, and
`--evidence-replay-mechanism-digest`. The gate accepts no prior replay receipt;
it calls the installed replay mechanism afresh for every assessment.

The expected replay denominator is derived independently from the installed
Tier 1 inventory as the exact 45 stable obligation identifiers. It is not read
from the submitted ledger. Every identifier requires exactly three distinct,
canonically ordered cases: `POSITIVE`, `NEGATIVE`, and `UNKNOWN`, for 135
selected test nodes. Tests whose basename begins with `test_self_polish` are
recursive evidence and are ineligible. A replay can clear the mechanical gate
only when its manifest and mechanism match both independent pins, its source
revision matches the selected source, all 135 nodes pass without global
invalidators, and its membership set exactly equals the installed denominator.
That replay receipt declares `scope: SELECTED_FILES_ONLY`; it cannot by itself
establish repository/package estate closure.

Each successful replay membership exposes a `stable_replay_digest` binding its
three selected cases and derived outcomes. The matching ledger row's
`independent_replay.receipt_digest` must equal that stable digest. The complete
self-representation's `representation_evidence_digest` must equal the replay's
`stable_replay_set_digest`, while its existing fields bind the exact source and
ledger. The top-level `receipt_digest`, `evidence_digest`, and `run_artifacts`
identify the fresh run event for audit; they are not substituted for the
stable row or representation bindings.

## Verdict rules

- Malformed, duplicated, substituted, stale, source-mismatched, or
  denominator-mismatched evidence is `FAIL`.
- Missing census inputs or any valid primary `UNKNOWN`, `NOT_ESTABLISHED`, or
  unobserved row keeps the tier `UNKNOWN` and
  `whole_tier_conformance: NOT_ESTABLISHED`.
- Provider coverage is orthogonal to the primary obligation verdict. A blocked,
  unavailable, or unreviewed provider remains visible in exact per-provider
  state counts and provider-coverage exception counts, but it does not by
  itself refute an obligation whose applicability, authority, observation,
  native assessment, implementation, focused validation, independent replay,
  final disposition, and evidence freshness are mechanically `PASS`. An
  explicit provider `FAIL` remains a refutation and cannot be hidden as an
  exception.
- Caller-authored `PASS` strings and SHA-256-shaped evidence digests establish
  neither replay nor independent review. They are reported only as declared
  status. `mechanical_replay_status` becomes `PASS` only after the fresh exact
  replay succeeds and every ledger row matches its replay membership's stable
  digest. `independent_evidence_status` becomes `PASS` only when the complete
  self-representation also binds the same stable replay set, exact ledger, and
  exact source, and binds a fresh candidate-estate evidence result whose own
  status and bounded full-estate closure are both `PASS`. Otherwise the
  statuses remain `NOT_ESTABLISHED` and the tier cannot return `PASS` or exit
  zero.
- After a successful selected-files replay, the adapter recaptures every
  Git-tracked working byte and compares the resulting HEAD, tree, worktree
  status, and manifest digest with the pre-replay coordinate. A mismatch is a
  definite `FAIL`. A matching recapture establishes source stability across
  that replay only; it does not prove that the registry enumerates the full
  source estate.
- The installed route inventory currently declares normative full-family
  closure `NOT_ESTABLISHED`, and the polish catalog declares objective
  inventory closure `NOT_ESTABLISHED`. The independently pinned census can
  enumerate repository/package/API/CLI/schema candidates, but it deliberately
  does not classify their semantic applicability or authenticate authority and
  evidence. Therefore an otherwise green 45-membership replay remains
  `status: UNKNOWN`, `selected_tier_status: UNKNOWN`, and
  `whole_tier_conformance: NOT_ESTABLISHED`, with blocker
  `REGISTRY_OR_FULL_ESTATE_CLOSURE_NOT_ESTABLISHED`; the CLI exits 2.
- A successfully pinned candidate-estate census is reported separately as
  `candidate_estate_census.mechanical_census_status: PASS`; an exact
  applicability subledger may similarly report mechanical validation `PASS`.
  Both retain semantic applicability and full-estate closure as
  `NOT_ESTABLISHED`, with blocker
  `CANDIDATE_ESTATE_SEMANTIC_CLOSURE_NOT_ESTABLISHED`. Missing census or ledger
  selections remain explicit blockers rather than being inferred from caller
  status strings.
- A complete, current, independently authenticated per-candidate replay may set
  `repository_package_estate.semantic_applicability_status`,
  `per_obligation_replay_status`, and `repository_package_estate_closure` to
  `PASS` for the exact mechanically enumerated candidate universe. This is a
  bounded estate subgate, not a Tier 1 verdict by itself. Tier 1 can return
  `PASS` only when the installed-route replay, ledger, self-representation,
  route and objective registries, structural crosswalk, stable full-source
  recapture, union, authority, dependency, interaction, and every other
  applicable prerequisite also pass. Missing evidence remains `UNKNOWN`; a
  refuted replay remains `FAIL`.
- Tier 2 rejects a retained tier-1 report that merely claims selected or
  whole-tier `PASS`. It cannot invoke Dynamics progression until whole-tier
  Facets replay is mechanically established at the current identical source
  and denominator.
- Ordinary JSON inputs remain limited to 8 MiB. The retained full Tier-1 report
  alone has a dedicated raw transport limit of 16 MiB because it carries the
  complete per-candidate result set. `--tier1-report` applies that limit to the
  exact file bytes, including any final newline; it does not truncate or
  compress the report. The JSON command-line emitter counts the exact sorted,
  indented Unicode Transformation Format, 8-bit (UTF-8) serialization plus its
  final newline and changes an oversized prospective Tier-1 `PASS` to `FAIL` with
  `TIER1_PASS_REPORT_TRANSPORT_CAPACITY_EXHAUSTED`.
- A retained Tier-1 report has an exact top-level field set. For a claimed
  `PASS`, the consumer freshly recaptures the complete candidate estate at the
  retained source coordinate, compares the exact census and estate digest,
  validates the applicability and configured-key authority result envelopes,
  and revalidates the estate-evidence result digest and the full candidate
  identity/result set. Rehashing an added field, truncated result list, nested
  substitution, or changed census therefore cannot promote Tier 2.
- The retained estate-authority envelope is exact in either of two forms: a
  current configured-key `PASS`, or the authority producer's canonical
  absent-receipt result (`UNKNOWN`, independent authority and replay
  `NOT_ESTABLISHED`, null policy and receipt, no actors, and exactly
  `ESTATE_AUTHORITY_RECEIPT_UNAVAILABLE`). The latter does not establish
  authority; it is retainable only because native Tier-1 estate verification
  is independent of configured-key authority. `FAIL`, rehashed arbitrary
  `UNKNOWN`, changed boundaries, and substituted subject bindings fail closed.
- `full_application_status` remains `UNKNOWN`, and `polished` and
  `release_authorized` remain false. A complete selected numeric tier would not
  establish full nine-tier application, release authority, or human
  acceptance.

The obligation-union validator establishes structural equality against an
externally selected candidate authority. Its semantic-completeness field
remains `UNKNOWN`; qualified scope admission and semantic replay must come from
installed mechanisms. A digest selects bytes but does not authenticate the
selector or prove the referenced evidence. The retained report digest is an
external byte-selection boundary, not authentication; callers must pin the
selected report independently.

Provider execution is outside this adapter. An unavailable provider is not a
reason to substitute another provider, weaken primary evidence requirements,
or strengthen a verdict. Provider declarations, including a digest-shaped
claimed `PASS`, never replace primary mechanical evidence replay. The current
provider records remain `CLAUDE_PROVIDER_BLOCKED` and
`ANTIGRAVITY_PROVIDER_BLOCKED`; neither has a qualifying receipt. Those states
are preserved as provider-coverage exceptions rather than silently relabeled
as completed reviews. Parsed ledger output exposes
`provider_review_status_counts`, `provider_state_counts`,
`provider_coverage_exception_count`,
`provider_coverage_exception_membership_count`, and
`provider_fail_status_count` so coverage gaps and explicit refutations remain
separately auditable.
