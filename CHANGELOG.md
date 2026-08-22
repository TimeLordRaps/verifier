# Changelog

## 1.1.2 - 2026-08-22

- Correct the SimulacraBench synthetic specimen additively: unobserved private
  artifacts now remain `IDENTIFIED`, and the public challenge stops at
  `CHALLENGED` without a founder-authored adjudication.
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
- Implement the fourteen-rung VSTD-4 refutability ladder and compute depth by
  iterated satisfiability rather than accepting a declared level.
- Add the `VSTD4-GDC-1` grounded decision-certificate format, independent bounded
  checker, Horn/unit-propagation tier, width-bounded and general-resolution tiers,
  and evidence-bearing `UNKNOWN` results on exhaustion.
- Add machine-readable refutation surfaces, precommitment envelopes, availability
  assessment, append-only challenge adjudication, monotonic degradation, and
  refutability closure.
- Compute VSTD-Graph level from membership, provenance closure, status, and edge
  evidence, with a certificate explaining the next unreachable level.
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
