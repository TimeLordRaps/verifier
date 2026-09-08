# Changelog

> **Acronyms:** artificial intelligence (AI); Advanced Micro Devices (AMD); application programming interface (API);
> Amazon Web Services (AWS); Concise Binary Object Representation (CBOR); continuous integration (CI);
> command-line interface (CLI); conjunctive normal form (CNF); CBOR Object Signing and Encryption (COSE);
> grounded decision certificate (GDC); Hypertext Transfer Protocol Secure (HTTPS);
> Internet Engineering Task Force (IETF); Java unit test report format (JUnit);
> JavaScript Object Notation (JSON); nondeterministic polynomial time (NP);
> reduced instruction set computer (RISC); Boolean satisfiability problem (SAT);
> Secure Hash Algorithm 256-bit (SHA-256); Secure Hash Algorithm 3 256-bit (SHA3-256);
> Supply Chain Integrity, Transparency, and Trust (SCITT); Secure Shell (SSH);
> Coordinated Universal Time (UTC); Verifier Standard (VSTD); ZIP archive format (ZIP);
> zero-identity/zero-knowledge (ZIZK).

## Unreleased

### Post-release clarification

- Clarify that `current-candidate evidence`, `final-main publication evidence`, and
  `unreleased source has passed it` in the immutable version 1.3.0 release notes describe
  the pre-publication review coordinate. Version 1.3.0 was published from tag `v1.3.0` at
  commit `adc0415ea653376ed3f4c146a84daac1f72913f6`; subsequent commits remain unreleased
  descendant source even while package metadata still reads 1.3.0. This clarification
  does not rewrite the tagged changelog or published release notes.

## 1.3.0 - 2026-09-08

### Integration contract preparation

- Carry each selected stored implementation's declared package dependencies into exact
  package-qualified planning prerequisites. Readiness no longer omits those obligations;
  retained dependency artifacts do not establish resolution or installation. Changed plans
  require fresh authorization-declaration bindings. Missing package bytes remain
  `NOT_ESTABLISHED`, and independently checkable plan substitutions remain `INVALID`.
  Registry-only planning and stored-format identifiers are unchanged.
- Define certifier as an explicit certificate-issuance capability, distinct from proving,
  checking and issuer authority. Existing relation, mechanism and native-contract metadata
  carry that capability without changing the closed component-kind enumeration or adding
  an unevidenced native integration. Supported analysis/comparison and experimental
  catalog, package, planning, readiness and topology interfaces remain distinct.
- Separate platform test intent from exact recorded observations and current-candidate
  evidence. Preserve platform skips, the pre-retarget observation coordinate, and the
  requirement for fresh integration and final-main publication evidence.
- Read release-verification Git blobs in one bounded raw-object batch, preserving exact
  path, byte and digest comparisons while avoiding one process launch per file. Reject
  malformed or misbound responses and retain rejection of archive export substitutions
  or omissions; no generated archive replaces the raw Git-byte comparison authority.
- Exclude local benchmark, type-checker and linter caches from the public presentation
  scan. Generated tool state is neither a publication surface nor stable input to release
  claim checks.

### Explicit graph topology interpretations

- Add experimental graph-bound topology contracts and `vstd data topology`: distinguish
  simultaneous Boolean equations from explicitly declared backward-time relations.
  Report self-reference, cyclic groups, forks, joins and disconnected components separately
  from bounded equation and clock-offset consistency. Paradox candidates remain annotations;
  unsupported semantics and exhausted bounds remain `NOT_ESTABLISHED`. No physical causation,
  receipt conformance or mechanism-earned support follows from these diagnostics.
- Register the typed checker for exact nonexecuting planning and configure its tests on all
  four existing platform coordinates. New registry/package/plan digests require fresh bindings;
  historical run evidence does not qualify this added component. Existing receipt formats and
  cyclic-assurance admission guards are unchanged. See [topology interpretation](docs/GRAPH_TOPOLOGY.md).
- Repair a dependency traversal that falsely reported a cycle in an acyclic branching graph;
  preserve genuine cycles, self-reference and deep-graph handling.

### Artifact awareness semantics

- Define artifact awareness, awareness relations, awareness boundaries and confidentiality
  of awareness. Separate actual awareness, permitted awareness and potentially inferable
  awareness, including indirect disclosure through composed artifacts.
- Surface prohibited awareness inferences in existing inspection, analysis, planning and
  readiness diagnostics. Permission does not establish knowledge; withholding direct access
  does not establish non-inferability.
- Add an experimental exact-graph-bound analyzer for finite observer-relative knowledge
  closure across composed higher-order interfaces. Conjunctive hyperpaths preserve the
  all-premise derivation; exact supported traversal is `FAIL`, incompatible relevant rule
  evidence remains `CONFLICTED`, missing evidence or exhausted bounds remain `UNKNOWN`, and
  `MATCH` requires complete bounded closure of the declared model. This is not an awareness
  tracker, universal non-inferability proof, runtime enforcement, authorization or actor
  attribution. Expanded diagnostics and the added catalog component require fresh package,
  plan and platform evidence. Receipt identifiers and the stored-package format are unchanged.
- Bind observer, interface, rule and completeness evidence to the exact graph digest;
  require interface sources and graph-backed rule inputs/outputs to match the strict graph
  snapshot exactly. Caller-selected identifiers and emitted relationship metadata can
  themselves disclose information, so analyzer contracts and reports inherit the source
  graph's confidentiality requirements.
- Bind complete fact records at observer, interface and rule support points; retain typed
  seed evidence and exact graph-backed steps in concrete witnesses. Use an explicit
  goal-directed bounded traversal schedule, while preserving `UNKNOWN` whenever its
  firing or depth limits prevent completed closure.

### Stored verifier-like components

- Add experimental `VSTD-COMPONENT-PACKAGE-1`: a bounded, self-contained JSON format
  retaining exact implementation artifact bytes, a strict catalog 1.1 registry,
  literal entry-point bindings, dependency declarations, and unsigned descriptive
  publisher/license metadata. Canonical package and artifact digests bind those bytes
  and declarations; they do not establish native correctness, authentic authorship,
  executable dependency completeness, or permission to execute.
- Add nonexecuting save/load/inspection functions, `vstd components inspect`, and
  `vstd surface analyze --plan --package` with optional expected package digests.
  Unknown formats, duplicate keys, broken bindings, tampered content, nonportable
  artifact names, and resource-bound violations fail closed. Loading never extracts,
  installs, fetches, or invokes a stored implementation.
- Bind package-aware plans and execution-readiness preflight to the exact revalidated
  package bytes, not only its registry. Changed payloads invalidate the plan binding;
  caller-supplied authorization declarations must bind the exact package-aware plan.
  Missing package bytes remain `NOT_ESTABLISHED`. Registry-only planning stays explicit,
  and these checks neither authenticate authority nor grant permission to execute.
- Add a source-snapshot exporter for the 19 first-party catalog entries and portable
  format specimens. Public hosting and native-runtime qualification remain separate
  gates; this stored-format foundation is part of the v1.3.0 interoperability scope.

### Surface analysis and experimental interoperability planning

- Add a strict zero-dependency VSTD-2 geometry loader, stable top-level modeled-surface
  analysis API, and deterministic nonexecuting `vstd surface analyze` command. The loader
  rejects duplicate keys, non-finite numbers, unknown fields, invalid types, and broken
  geometry references before analysis.
- Add an explicitly experimental `verifier.interoperability` planning facade for
  immutable, domain-neutral component descriptors and registries plus deterministic,
  registry-digest-bound candidate plans. Keep the catalog and planner names outside the
  supported top-level `verifier.__all__` boundary. Catalog schema 1.1 separates the
  VSTD-2 planning-surface coordinate from schemas actually accepted by each native entry
  point; strict 1.0 migration preserves planning matches without inventing native input
  compatibility.
- Populate a first-party planning catalog with 19 exact implementation entry points across
  12 explicitly counted catalog grouping labels, and expose it through the nonexecuting
  `vstd surface analyze --plan` path. The denominator is not a count of independent or
  external native verifiers.
- Add a runnable non-critical sorted-grocery-list example that produces two exact
  candidates and leaves three self-closure holes unmatched without invoking its checker.
  Planning is not validation execution: component execution, evidence collection,
  post-execution reanalysis, safety, and critical-domain readiness remain unsupported or
  unestablished. Modeled closure is bounded to the supplied geometry.
- Add explicit `examples/` and `experiments/` directory maturity guidance and a
  component-by-component platform-interoperability evidence matrix.
- Add a non-critical executable proof-producing-solver to proof-checker composition with
  exact formula, proof, implementation, registry, and component-entry bindings. The
  checker rehydrates the canonical transition bytes and rejects modified proof or catalog
  coordinates before checking. The serialized transition also binds the current producer
  and checker implementation digest, and malformed canonical formula structures return a
  deterministic rejection instead of escaping the typed result. Forged-proof,
  wrong-formula, truncated-proof, transition-mutation, and bound-exhaustion tests remain
  fail-closed. Together with the existing
  SCITT example, this provides two bounded composition geometries without claiming actor
  independence, external interoperability, or safety.
- Qualify the cryptographic SCITT example against the exact installed `scitt-cose==0.2.2`,
  `cbor2==6.1.4`, and `cryptography==50.0.0` distributions before native calls. Record the
  statement/receipt verification entry points and direct dependency versions in the local
  result while keeping them out of the producer-signed payload and native component
  catalog. These coordinates observe one verifier runtime; they do not authenticate its
  packages, identify the producer, or establish independent interoperability.
- Add an experimental declaration-bound cross-geometry diagnostic with deterministic
  witnesses for explicit `VERIFIED` versus `FALSIFIED` judgments and cycles in dependencies
  declared acyclic. Missing shared identity and indeterminate judgments remain
  `NOT_ESTABLISHED`; malformed bindings are `INVALID`. This is structural analysis, not
  Boolean satisfiability analysis or evidence of physical truth, safety, or conformance.
- Add an experimental nonexecuting execution-readiness preflight that binds an exact
  analysis, plan, and registry to native-input digests, planned result-to-evidence mappings,
  evidenced prerequisite resolutions, a caller-supplied authorization decision, and a
  mandatory post-execution reassessment contract. `READY` establishes only internal
  completeness of those declarations; it neither executes nor authorizes a component.

### Cross-platform comparison

- Add a supported bounded comparator and `vstd compare-platforms` command for VSTD-1
  generic-run receipts. A declaration alone earns no result: `PASS` requires one
  canonically intact receipt per declared operating system, matching non-platform
  bindings, and matching declared result projections. Preserve comparable disagreement
  as `CONFLICTED`, incomplete or non-comparable evidence as `NOT_ESTABLISHED`, and
  malformed or contradictory evidence as `INVALID`.
- Bind Python implementation and machine identity into newly captured comparison
  declarations. Legacy receipts retain their historical canonical-digest semantics but
  cannot establish comparison without this additive environment binding; a mismatch
  between bound and reported environment data is `INVALID`.
- Add native GitHub-hosted Linux, Windows, and Intel macOS observation jobs for the
  portable generic example and require their aggregate diagnostic in the protected
  repository-check gate. Make the example's declared JavaScript Object Notation outputs
  use explicit line-feed bytes so Windows text translation cannot create a false portable
  surface. Extend release-artifact byte comparison to macOS. These checks
  do not establish universal portability, native-execution attestation within the
  receipt, semantic correctness, or actor independence.
- Add a separate complete Python contract matrix for Linux x86-64, Windows x86-64,
  macOS Intel, and macOS ARM64, including the optional artifact-seal and cryptographic
  SCITT profiles. Its diagnostic artifact binds the pull-request head and base, executed
  checkout, runner image, operating system, machine, interpreter, run identifier, and
  attempt before installation; its JUnit report preserves platform-specific skips and the
  available raw evidence is retained after failure. Emit report bytes with explicit
  platform-neutral line feeds, reject contradictory JUnit suite counts and non-exact
  environment records, and bind the raw environment-document digest. The release workflow requires an exact successful push run
  on the protected default branch, reconstructs all four reports from their raw environment
  and JUnit evidence, and attaches an attested deterministic platform-evidence ZIP with its
  own internal digest manifest. Configuring this matrix is not evidence that the unreleased
  source has passed it.

## 1.2.0 - 2026-09-01

### Public surface and integrations

- Restructure the public first-view path around one bounded project description, one
  deterministic demonstration, one canonical maturity table, skeptical claim limits,
  contributor routes, and release/citation boundaries; align Pages and package metadata
  without changing normative or serialized-receipt semantics.
- Normalize the public architecture as a verification complex of named closure
  coordinates and cumulative numbered profiles; reserve VSTD-4 rung, candidate depth,
  verification order, compatibility level, and checker-cost tier for their distinct uses.
- Add experimental workflow profile 0.1 with deterministic canonicalization, strict
  validation, bounded work-allocation records, additive amendments and challenges,
  explicit unresolved horizons, and verdict-neutral platform events.
- Add a normalized GitHub adapter for issues, commits, workflow runs, artifacts, and
  pull requests. Successful workflows and merges retain `verification_effect = NONE`
  unless a separate native result is explicitly mapped through a bound VSTD receipt.
- Add `vstd experiment validate` and `vstd experiment github-events` as offline,
  verdict-neutral entry points. Repository artifacts are explicitly `NOT_CHECKED` with
  exit code 2 unless their root is supplied.
- Add a machine-readable schema, checked-in verdict-neutral specimen, generated
  experiment index, adversarial tests, and a runnable offline example.
- Add a generated CLI/API reference page and presentation gates that reject stale
  reference or experiment-index content.
- Clarify VSTD's role as a verification-domain language and interchange layer that
  preserves, rather than replaces or strengthens, native verifier results.
- Add the experimental SCITT adapter, rerunnable real-COSE specimen with ephemeral keys, explicit semantic
  boundary, and adversarial composition tests without claiming IETF review or payload
  truth from registration.
- Surface zero-identity/zero-knowledge (ZIZK) artifact-first TRUST as governing
  architecture, publish the bounded RISC Zero reference mechanism and exact recorded
  public proof artifacts, and keep only unfinished mechanisms experimental while
  preserving unresolved horizons and native-system authority.
- Bind the recorded RISC Zero proof to the image produced from the tracked guest and
  locked toolchain in the governed offline verifier, rather than accepting source/proof
  correspondence from a neighboring historical image identifier.
- Formally distinguish TRUST as mechanism-earned forward artifact support, ROT as typed
  time-indexed degradation of current admissibility, and RUST as an inverse-TRUST memetic
  causal backtrace toward recorded ancestor states. None is actor-tied trust or a scalar;
  reachability alone never infers guilt, responsibility, or causal localization.
- Present current reports, schemas, module descriptions, and examples under the full
  VSTD-1 and VSTD-2 numbered-profile identifiers; remove retired partial-profile object identifiers from
  active readers and add a regression preventing their return.
- Add normative artifact-control mechanism version 1 with exact-byte file/directory
  freezing, SHA-256 plus SHA3-256 artifact-derived identities, observable read-only
  guards, readable finite self-closing Ed25519 seals, external anchor checks, and
  copy-on-write thaw descendants. Sealing is not encryption and supplies no actor trust,
  semantic correctness, trusted time, or numbered VSTD profile result.
- Document multi-temporal realms, discrete and continuous coexistence, causal and
  problem-space partial orders, atemporal versus temporal capsules, explicit cross-realm
  mappings, and future constrained language-model transition verification without
  claiming continuous mediation, inference-law implementation, or textual truth.

### Claim boundaries and validation

- Require `thawed_artifact_status` and `vstd artifact status` to verify an actual supplied,
  cleanly sealed parent and every recorded parent coordinate before returning
  `THAWED_CLEAN` or `THAWED_DIRTY`. Sidecar-only agreement is now `NOT_ESTABLISHED`; even a
  verified current match does not authenticate the historical copy operation or external
  parent continuity.
- Preserve final filesystem-entry identity during artifact creation: freeze refuses
  symbolic-link sources, and bundle, thaw-descendant, and sidecar outputs refuse every
  preexisting lexical entry, including dangling symbolic links, without claiming universal
  race-free filesystem security.
- Require authoritative freeze-manifest, payload, seals-container, and seal-envelope
  members to have ordinary lexical types; linked external or in-bundle targets cannot lend
  bytes to bundle closure, while verified outer read aliases and ordinary hard-link
  byte-and-path semantics remain explicitly distinct.
- Remove the live SimulacraBench rehearsal and its front-door promotion; the repository
  never contained or reproduced the submission, hosted image, hardware, or protected
  evaluation identified by that name.
- Correct generic-run wording: digest validation is an integrity check, external
  references remain unattested until dereferenced and verified, same-path output
  extraction is not independent verification, and unverified determinism is `UNKNOWN`.
- Publish a Pages guide index and enforce language, title, viewport, main-region, skip-link,
  image-alt, labelled-navigation, generated-reference, and local-link checks in CI.
- Preserve explicit ordered-list starting numbers in generated Pages so procedures split
  by code blocks retain their source step numbers instead of restarting at one.
- Require CodeQL security-extended Python analysis in the protected repository-check
  aggregate with only read access to content and write access to security results.
- Fail closed on malformed generic-run receipts, publish their exact schema, and dispatch
  `VSTD-1` by its required receipt profile.
- Package every normative specification, verify byte identity, and smoke-test the built
  wheel outside the source checkout so installed specification bindings cannot silently
  become unavailable.
- Bind the bundled checker to VSTD-1, record actor and execution separation explicitly,
  and never infer independent actors from a historical field name, repeated runs, or
  matching results.
- Reject self-promoted independence even when every supplied status and digest agrees;
  the generic-run compatibility path never derives `EVIDENCED` from serialized references.
  The distinct VSTD-5 path reruns all seven separation propositions and does not upgrade
  the legacy generic-run fields.
- Require the real optional SCITT/COSE cryptographic example in the protected
  repository-check aggregate
  rather than allowing its dependency-gated tests to disappear from the base matrix.
- Close generic-run control structures while retaining the released refutation-extension
  map, make common receipt commands honor `--json`, and lock `validate` as an
  integrity/profile check rather than a claim verifier.

### Graph and conformance semantics

- Add a zero-dependency evidence execution core that resolves and rehashes exact evidence
  bytes, pins a registered mechanism implementation digest, enforces byte/item bounds,
  reruns the mechanism, and preserves `PASS`, `FAIL`, or `UNKNOWN` under explicit trust roots.
- Add an evidence-bound VSTD-4 path and replayable receipt form. Compatibility
  `vstd4_depth` remains a `NOT_ESTABLISHED` candidate; only exact passing VSTD-1/2/3 and
  fourteen-rung mechanisms plus an accepted kernel witness admit VSTD-5.
- Implement the VSTD-5 reference mechanism and receipt: seven evidence-bound separation
  dimensions, duplicate-witness/evidence refusal, exact admitted-certificate and
  corroboration binding, typed binding/identity/separation/corroboration errors,
  disagreement preservation, embedded evidence, and offline result recheck. Independence
  fails closed on any identity or separation defect without parsing error-message text.
  Witness identities and assertions serialize separately and in order, so duplicate,
  orphan, missing, and reused-identity error inputs remain replayable instead of collapsing
  during receipt construction. Keep permissive malformed-input assessment distinct from
  portable receipt admission: the builder now raises unless the strict schema and complete
  verdict-material evidence coverage hold, and the rechecker applies the same zero-dependency
  gate before replay. The rechecker also compares the complete carried VSTD-4 entry, and
  `corroboration_class` is mechanism-bound rather than relabelable metadata. This does not
  claim a real external witness or independent implementation; a positive observation with
  unresolved independence is overall `UNKNOWN`.
- Add evidence-bound Graph profile computation and replay. The compatibility `graph_level`
  path remains caller-supplied; the new path reruns every member, ancestor, and reached-edge
  rating mechanism bound to the exact Graph, members, collection, and claim before profile
  1–5 can report `ESTABLISHED`. Profile zero remains `NOT_ESTABLISHED`.
- Add `VSTD-GRAPH-ASSURANCE-1` and `AssuranceLedger` for hash-chained edge-local TRUST, ROT, RUST,
  challenge-ledger projection, additive conflict declaration/resolution, structural RUST concentration,
  explicit causal localization, and bounded artifact-relative BLAME/GUILT propositions.
  Each TRUST event binds one exact transformation, its inputs/output, the historical Graph,
  and prerequisite TRUST events; current eligibility recursively fails closed when any bound
  dependency degrades or conflicts. Duplicate paths remain set-valued, historical graph bytes
  remain immutable, and topology alone earns no causal or moral conclusion. BLAME establishes
  bounded responsibility or material contribution. GUILT is not BLAME in the opposite
  direction: it composes separately bound responsibility, exact scoped-obligation
  applicability, and same-obligation violation components, then binds their exact event
  digests. One compound mechanism may emit all three component evaluations in one invocation;
  an opaque combined pass or decorative obligation string remains `NOT_ESTABLISHED`.
  Localization binds one exact passing RUST event and descendant-deviation proposition.
  Neither result establishes actor morality, reputation, automatic legal liability,
  innocence, exoneration, obligation satisfaction, or absence of hidden contributors.
  Status-conflict resolution projects the
  selected state into current admissibility; arbitrary resolved predicates remain blocked.
  The current runtime has no general non-status admissibility-effect mechanism. RUST follows
  historically recorded contributing ancestry even when current lifecycle state excludes a
  route from TRUST. New construction, evidence-bound Graph establishment, and assurance
  propagation require globally disjoint artifact/transformation identifiers so an untyped
  `subject_id` cannot ambiguously name both; the frozen `VSTD-DATA-0.1` reader retains its
  original two namespaces.
  Add complete offline event replay,
  current TRUST filtering, and deduplicated descendant reassessment discovery.

- Preserve incompatible Graph assertions as evidence-linked conflict records and label
  rating-derived Graph profile numbers as `CALLER_SUPPLIED` candidates with conformance `NOT_ESTABLISHED`.
- Classify the current VSTD-4 candidate-depth calculation as a structural result over
  caller-supplied rung references with conformance `NOT_ESTABLISHED`; reject that
  candidate at the VSTD-5 entry gate even when its candidate depth is 14.
- Label compatibility Graph 2–5 candidates consistently while separately presenting the
  implemented evidence-bound reference paths. Bind complete challenge-ledger state into an
  additive current Graph view without mutating history.

### Release and maintainer controls

- Mark 1.2.0 metadata as an unreleased release candidate, omit any fabricated release
  date, and require the exact tagged checkout to have `TIME.md` set to `Status: CLEAR`.
- Move the immutable-release setting check before tag creation in the documented release
  sequence and enforce it again in the tag workflow, so a disabled setting stops
  publication rather than producing a mutable release.
- Make package/reference status identify VSTD-5 as the highest exposed project
  specification with an evidence-bound reference mechanism, without claiming a real
  independent witness, and require finalized release metadata in the tag workflow.
- Publish the architecture ownership map linking normative documents, runtime validators,
  schemas, and conformance tests.
- Document the five-As human traversal over existing receipt, Graph, hardware, certificate,
  reproduction, and SCITT machinery without adding a serialized receipt format; reject duplicate Graph
  identifiers and reproduction-fidelity states inferred from declarations, matching verdicts, or
  mismatching runs.
- Restore the three non-overlapping operating controls: `AGENTS.md` for automated work,
  `HUMANS.md` for human five-As reasoning, and `TIME.md` for current repository
  contradictions. Development may record `OPEN`; the exact tagged checkout must be
  `CLEAR` before publication.
- Replace the developmental profile-numbered generic-run container with required neutral
  `assessment_context`; preserve its mechanism, bound, commitment, and refutation
  coordinates without carrying a VSTD-4 conformance field.

## 1.1.3 - 2026-08-22

- Canonicalize source ZIP timestamps in UTC and remove host ZIP metadata, so the
  same Git coordinate produces byte-identical source archives on Windows and Linux.
- Canonicalize generated wheel and source-distribution newlines, archive member
  order, modes, timestamps, and ownership. Rebuild wheel `RECORD` after normalization
  and use compression-independent ZIP members plus a stable `ustar`/gzip container.
- Normalize common HTTPS and SSH spellings of the Git origin before recording the
  public repository coordinate in a release manifest.
- Require CI to build the complete release artifact set independently on Windows and
  Linux and fail the conformance gate unless every resulting byte is identical.
- Record that `v1.1.2` remained a signed, tested, and attested GitHub-only release:
  its protected PyPI deployment was cancelled after cross-platform build differences
  were detected, before any Python distribution was uploaded.

## 1.1.2 - 2026-08-22

- Rename the import package `verifiable` to `verifier` and the distribution
  `verifiable-standard` to `verifier-standard`, so no published name reuses the ordinary-English
  adjective or the maintainer's former project name. The `vstd`, `verifier`, and
  `verifiable` command names all continue to work; `verifiable` is a command name only
  and no longer names an import package.
- Derive the release source-archive name from the manifest during verification, so
  manifests published through `v1.1.1` that bind `verifiable-standard-<release>.zip`
  remain verifiable without republishing.
- Record the import-package, distribution, and archive renames in
  `WIRE_IDENTIFIERS.md`. No receipt serialized receipt identifier, schema `$id`, or canonical digest
  changes.
- Attribute the specifications, distribution metadata, and governance decision rights to
  `TimeLordRaps`. The legal name remains the copyright holder in `NOTICE`.
- Add a normalized, byte-reproducible Python source distribution beside the reproducible
  wheel; verify their name, version, import package, and frozen console-script set before
  release.
- Publish only the tested wheel and source distribution through PyPI Trusted Publishing
  after explicit approval in the protected `pypi` environment. The GitHub release keeps
  the full source ZIP and external byte manifest as the public provenance coordinate.
- Document that the unrelated PyPI project named `verifier` shares the same import name
  and must not be co-installed; this is an ecosystem collision boundary, not a claim to
  that distribution coordinate.

- Rename the VSTD-2 section 7 lifecycle term `VERIFIABLE` to `GEOMETRY_INSPECTABLE`
  and record in `WIRE_IDENTIFIERS.md` that the section 7 vocabulary is prose-only, so
  no status token reuses the maintainer's name and no serialized receipt value changes.
- Label the reference emulator's synthetic accelerator descriptor `vendor` as
  `EMULATED` instead of the maintainer's name, so fabricated hardware evidence cannot
  read as maintainer attestation.
- Remove maintainer-scoped phrasing from normative specification prose: conformance is
  defined by the documents, and the independent auditor role is named by the standard
  rather than by the maintainer.

- Correct the SimulacraBench synthetic specimen additively: unobserved private
  artifacts now remain `IDENTIFIED`, and the public challenge stops at
  `CHALLENGED` without a maintainer-authored adjudication.
- Require content-bound observed bytes before deriving `AVAILABLE` or `PORTABLE`;
  locator and retention declarations alone no longer elevate availability.
- Expand the public presentation gate to reject drive-qualified paths, private
  locator schemes, deployment fields, local model artifact filenames, business
  operations identifiers, common secret shapes, and email addresses.

## 1.1.1 - 2026-08-22

- Replace the overview's generic maturity badges with the exact status of every
  object and Graph numbered profile, so the presentation cannot imply evidence or
  implementation maturity that the specifications do not establish.
- Enforce those visual labels in the presentation gate and publish canonical
  receipt schemas at their declared GitHub Pages `$id` routes.
- Add contributor guardrails for the live schema routes, the Python 3.10 floor,
  and the immediate-publication consequences of edits to Pages content.

## 1.1.0 - 2026-08-22

- Add `vstd demo`, a deterministic four-scenario adversarial demonstration that
  rejects a proof grounded to the wrong artifact, preserves a checked `UNKNOWN`,
  rejects verification-cost inflation, and exposes a revoked transitive ancestor.
- Publish the replayable demo specimens, a newcomer quickstart, a public technical
  roadmap, an ecosystem boundary map, and a focused project overview site.
- Make `vstd` the canonical cross-platform command while retaining `verifier` and
  `verifiable` as compatibility aliases. This avoids collision with Windows Driver
  Verifier without breaking previously issued command references.
- Replace the unused adopter-migration document name with an implementation
  compatibility note; no external adoption or adopter migration is implied.
- Add automated checks for documentation links, version agreement, public-boundary
  language, packaged demo behavior, and checked-in specimen determinism.
- Add repository-level instructions that keep automated contributors inside VSTD's
  fail-closed claim, dependency, compatibility, and public/private boundaries.

## 1.0.1 - 2026-08-22

- State explicitly that each VSTD closure coordinate requires its own evidence:
  Refutability does not supply, entail, upgrade, or repair prerequisite coordinates.
- Replace unsupported Tarski, generic NP-certificate, CNF-equals-3-SAT, and
  physical-world co-NP claims with bounded statements tied to implemented formal
  languages and declared observation surfaces.
- Replace adopter-migration framing with an exact current wire-dispatch registry; no
  external adoption is claimed.
- Generate source releases from exact public Git objects and publish a separate
  manifest binding the resolvable ref, commit, archive digest, file set, and member
  bytes. Line-ending equivalence is not accepted as byte identity.
- Add a side-effect-free manifest plan command and make unsandboxed execution visible
  at the CLI and README boundary without pretending declared-path checks sandbox the
  subprocess.
- Test the advertised Python 3.10 through 3.13 range, add release-integrity and
  installed-wheel jobs, and expose one required conformance gate for branch protection.
- Add an owner-dispatched release workflow for an existing tag that refuses a
  non-default-branch dispatch or a tag outside protected history, requires the protected
  conformance check and an owner-confirmed immutable-release preflight, rebuilds and
  smoke-tests exact artifacts, records tag signature status without relabeling it, and
  creates GitHub/Sigstore attestations for every uploaded asset.
- Add structured ambiguity, counterexample, and implementation feedback surfaces plus
  public conduct and pull-request consequence checks.

## 1.0.0 - 2026-08-22

- Redesign specification numbers as cumulative numbered profiles: VSTD-1 through
  VSTD-5 on the object axis and VSTD-Graph-1 through VSTD-Graph-5 on the
  collection axis.
- Establish integer numbered-profile specification paths while release history remains available in
  the corresponding Git tags.
- Add the fourteen-rung VSTD-4 structural calculation and compute its candidate depth by
  iterated satisfiability rather than copying a declared depth. Version 1.2.0 clarifies
  that its caller-supplied references do not establish VSTD-4 conformance.
- Add the `VSTD4-GDC-1` grounded decision-certificate format, independent bounded
  checker, Horn/unit-propagation tier, width-bounded and general-resolution tiers,
  and evidence-bearing `UNKNOWN` results on exhaustion.
- Add machine-readable refutation surfaces, precommitment envelopes, availability
  assessment, append-only challenge adjudication, monotonic degradation, and
  refutability closure.
- Preserve the historical `graph_level` compatibility calculation from membership, provenance closure,
  status, and caller-supplied edge ratings, with a certificate explaining the next
  unreachable candidate Graph profile. Version 1.2.0 labels conformance `NOT_ESTABLISHED`.
- Replace fabricated conflict evidence, literal trust-boundary claims, and
  decorative policy certificates with checked evidence and fail-closed divergence.
- Publish a draft VSTD-5 witness-corroboration interface. No independent witness
  implementation or interoperability claim is included.
- Move profile-specific documentation under `docs/` and publish schemas with stable
  compatibility filenames and paths.

## 0.2.0 - 2026-08-21

- Implement VSTD-3.0 Universal Accelerator Accountability without changing earlier
  receipt semantics.
- Add strict deterministic VSTD 3 types and JSON Schemas, plus a data-driven registry
  covering 37 accelerator/supporting-device profiles.
- Add the virtual firmware accountability state machine, nonce-bound test attestation,
  typed compute accounting, authenticated continuity, reset epochs, and local/file
  anchor interfaces.
- Add partition/topology and enrolled-fleet verification with physical/logical
  double-counting protection.
- Add generic, NVIDIA, AMD, Intel, and Google/AWS/Microsoft provider fixture boundaries.
  Opaque vendor evidence is preserved without invented verification.
- Compose device, firmware, execution, accounting, continuity, and provider evidence
  into the existing provenance hypergraph and blast-radius implementation.
- Add `hardware`, `continuity`, `fleet`, `evidence`, and `claims` CLI command families
  with JSON and explicit `PASS`/`FAIL`/`UNKNOWN`/`UNSUPPORTED` results.
- Add adversarial, epistemic, canonicalization, schema, provenance, adapter, CLI, and
  backward-compatibility tests.
- Publish a VSTD 3 threat model, vendor integration kit, migration guide, primary-source
  references, and claim-by-claim plain-language translations.

## 0.1.0 - 2026-08-21

- Publish the initial claim-mechanics, provenance-graph, and experimental
  verification-geometry surfaces.
- Publish zero-required-dependency receipt, provenance, geometry, and policy primitives.
- Publish an optional logits-level constraint kernel with atomic dependency profiles.
- Add a target-neutral public CLI for generic-run and stored VSTD-DATA receipts.
- Fail closed on malformed provenance graphs, inflated coverage metrics, dangling
  references, and omitted artifact status.
- Clarify that digest, license, and policy fields bind recorded declarations rather
  than proving real-world truth or complete lineage.
- Add a non-normative predictive-AI and competition-evaluation integration profile.
- Add a plain-language claim translation guide stating why each bounded claim can or
  cannot be made and what evidence it requires.
- Explicitly exclude private operational material and target-specific adapters.
- Release the specification, documentation, and reference implementation under the
  Apache License 2.0 with a repository `NOTICE` file.
