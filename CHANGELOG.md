# Changelog

> **Acronyms:** artificial intelligence (AI); Advanced Micro Devices (AMD); application programming interface (API);
> Amazon Web Services (AWS); Concise Binary Object Representation (CBOR); continuous integration (CI);
> command-line interface (CLI); conjunctive normal form (CNF); CBOR Object Signing and Encryption (COSE);
> grounded decision certificate (GDC); Hypertext Transfer Protocol Secure (HTTPS);
> Internet Engineering Task Force (IETF); JavaScript Object Notation (JSON); nondeterministic polynomial time (NP);
> Boolean satisfiability problem (SAT); Supply Chain Integrity, Transparency, and Trust (SCITT); Secure Shell (SSH);
> Coordinated Universal Time (UTC); Verifier Standard (VSTD); ZIP archive format (ZIP);
> zero-identity/zero-knowledge (ZIZK).

## 1.2.0 - UNRELEASED

- Restructure the public first-view path around one bounded project description, one
  deterministic demonstration, one canonical maturity table, skeptical claim limits,
  contributor routes, and release/citation boundaries; align Pages and package metadata
  without changing normative or wire semantics.
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
- Add the bounded ZIZK experiment and documentation-lineage guide while preserving
  unresolved horizons and native-system authority.
- Remove the live SimulacraBench rehearsal and its front-door promotion; the repository
  never contained or reproduced the submission, hosted image, hardware, or protected
  evaluation identified by that name.
- Correct generic-run wording: digest validation is an integrity check, external
  references remain unattested until dereferenced and verified, same-path output
  extraction is not independent verification, and unverified determinism is `UNKNOWN`.
- Publish a Pages guide index and enforce language, title, viewport, main-region, skip-link,
  image-alt, labelled-navigation, generated-reference, and local-link checks in CI.
- Fail closed on malformed generic-run receipts, publish their exact schema, and dispatch
  the frozen `VSTD-0.1` wire identifier by required receipt profile.
- Package every normative specification, verify byte identity, and smoke-test the built
  wheel outside the source checkout so installed specification bindings cannot silently
  become unavailable.
- Bind the bundled checker to VSTD-1, record actor and execution separation explicitly,
  and never infer independent actors from a historical field name, repeated runs, or
  matching results.
- Reject self-promoted independence even when every supplied status and digest agrees;
  version 1.2.0 has no actor/execution evidence-binding adapter and therefore never
  derives `EVIDENCED` from serialized references.
- Require the real optional SCITT/COSE cryptographic example in the conformance gate
  rather than allowing its dependency-gated tests to disappear from the base matrix.
- Close generic-run control structures while retaining the released refutation-extension
  map, make common receipt commands honor `--json`, and lock `validate` as an
  integrity/profile check rather than a claim verifier.
- Preserve incompatible Graph assertions as evidence-linked conflict records and label
  rating-derived levels as `CALLER_SUPPLIED` candidates with conformance `NOT_ESTABLISHED`.
- Classify the current VSTD-4 depth calculation as a structural candidate over
  caller-supplied rung references with conformance `NOT_ESTABLISHED`; reject that
  candidate at the VSTD-5 entry gate even when its candidate depth is 14.
- Label Graph 2-4 candidates consistently on first-view, documentation, command, schema,
  and SCITT surfaces. Keep challenge-ledger state, degradation from status already
  recorded in a Graph, and the missing challenge-to-Graph adapter distinct.
- Mark 1.2.0 metadata as an unreleased release candidate, omit any fabricated release
  date, and require the exact tagged checkout to have `TIME.md` set to `Status: CLEAR`.
- Make package/reference status explicitly say VSTD-4 candidate conformance is
  `NOT_ESTABLISHED`, and require finalized release metadata in the tag workflow.
- Publish the architecture ownership map linking normative documents, runtime validators,
  schemas, and conformance tests.
- Document the five-As human traversal over existing receipt, Graph, hardware, certificate,
  reproduction, and SCITT machinery without adding a wire format; reject duplicate Graph
  identifiers and reproduction levels inferred from declarations, matching verdicts, or
  mismatching runs.
- Restore the three non-overlapping operating controls: `AGENTS.md` for automated work,
  `HUMANS.md` for human five-As reasoning, and `TIME.md` for current repository
  contradictions. Development may record `OPEN`; the exact tagged checkout must be
  `CLEAR` before publication.
- Classify generic-run `layer4_binding` as a legacy wire container rather than a layer
  abstraction. Preserve pre-version-1.0 and version-1.x reads, keep current writes lossless
  under the frozen profile, and require an explicit later profile/schema boundary before
  replacing it; only `vstd4_conformance = NOT_EVALUATED` is accepted.

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
  `WIRE_IDENTIFIERS.md`. No receipt wire identifier, schema `$id`, or canonical digest
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
  no status token reuses the maintainer's name and no wire value changes.
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
  object and graph layer, so the presentation cannot imply evidence or
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

- State explicitly that each VSTD layer requires its own evidence: layer 4 does not
  supply, entail, upgrade, or repair layers 3, 2, or 1.
- Replace unsupported Tarski, generic NP-certificate, CNF-equals-3-SAT, and
  physical-world co-NP claims with bounded statements tied to implemented formal
  languages and declared observation surfaces.
- Replace adopter-migration framing with a frozen wire-identifier and historical
  project-filename registry; no external adoption is claimed.
- Generate source releases from exact public Git objects and publish a separate
  manifest binding the resolvable ref, commit, archive digest, file set, and member
  bytes. Line-ending equivalence is not accepted as byte identity.
- Add a side-effect-free manifest plan command and make unsandboxed execution visible
  at the CLI and README boundary without pretending declared-path checks sandbox the
  subprocess.
- Test the advertised Python 3.10 through 3.13 range, add release-integrity and
  installed-wheel jobs, and expose one required conformance gate for branch protection.
- Add a tag-triggered release workflow that refuses non-main or unconformed commits,
  rebuilds and smoke-tests exact artifacts, records tag signature status without
  relabeling it, and creates GitHub/Sigstore attestations for every uploaded asset.
- Add structured ambiguity, counterexample, and implementation feedback surfaces plus
  public conduct and pull-request consequence checks.

## 1.0.0 - 2026-08-22

- Redesign specification numbers as verification-depth layers: VSTD-1 through
  VSTD-5 on the object axis and VSTD-Graph-1 through VSTD-Graph-5 on the
  collection axis.
- Hard-rename the historical specification paths while preserving issued receipt
  wire identifiers and the `v0.1.0` and `v0.2.0` release history.
- Add the fourteen-rung VSTD-4 structural calculation and compute its candidate depth by
  iterated satisfiability rather than copying a declared level. Version 1.2.0 clarifies
  that its caller-supplied references do not establish VSTD-4 conformance.
- Add the `VSTD4-GDC-1` grounded decision-certificate format, independent bounded
  checker, Horn/unit-propagation tier, width-bounded and general-resolution tiers,
  and evidence-bearing `UNKNOWN` results on exhaustion.
- Add machine-readable refutation surfaces, precommitment envelopes, availability
  assessment, append-only challenge adjudication, monotonic degradation, and
  refutability closure.
- Add the historical VSTD-Graph level calculation from membership, provenance closure,
  status, and caller-supplied edge ratings, with a certificate explaining the next
  unreachable candidate level. Version 1.2.0 labels conformance `NOT_ESTABLISHED`.
- Replace fabricated conflict evidence, literal trust-boundary claims, and
  decorative policy certificates with checked evidence and fail-closed divergence.
- Publish a draft VSTD-5 witness-corroboration interface. No independent witness
  implementation or interoperability claim is included.
- Move layer-specific and profile documentation under `docs/` and publish schemas
  with stable layer-oriented filenames.

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

- Publish VSTD-0.1, VSTD-DATA-0.1, and experimental VSTD-0.2.
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
