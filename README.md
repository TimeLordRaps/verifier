<div align="center">

# Verifier Standard (VSTD)

**Portable, bounded, refutable evidence for computational claims.**

[![Conformance](https://github.com/TimeLordRaps/verifier/actions/workflows/ci.yml/badge.svg)](https://github.com/TimeLordRaps/verifier/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/TimeLordRaps/verifier?display_name=tag&sort=semver)](https://github.com/TimeLordRaps/verifier/releases/latest)
[![Python 3.10–3.13](https://img.shields.io/badge/python-3.10%E2%80%933.13-3776AB.svg)](https://www.python.org/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-2f7d6d.svg)](LICENSE)
[![Status: alpha](https://img.shields.io/badge/status-alpha-d97706.svg)](#current-maturity)

</div>

> **Acronym used below:** reduced instruction set computer (RISC).

VSTD is a verification-domain language and Python reference implementation for packaging
bounded computational claims with their evidence, checking mechanisms, limits,
refutation conditions, provenance, and reproducibility information. It does **not**
replace native domain verifiers, proof systems, signatures, identity systems,
transparency logs, or provenance formats, and it never strengthens their results merely
by translating or storing them.

It addresses a practical review problem: a final answer or green check rarely says
exactly what was checked, which evidence was used, where the conclusion stops, or what
would overturn it. VSTD carries those boundaries with the result.

**Current boundary:** implemented reference paths cover receipts, generic computation
capture, provenance graphs, verification geometry, accelerator evidence, grounded
certificate checking, reproduction, and a flagship adversarial demo. VSTD-4 depth and
Graph layers 2–5 are candidate computations with conformance `NOT_ESTABLISHED`;
VSTD-5 is not implemented. See [current maturity](#current-maturity) and
[claims and limits](docs/CLAIMS_AND_LIMITS.md).

[Normative specifications](standard/LADDER.md) ·
[60-second quickstart](docs/QUICKSTART.md) ·
[Implementation reference](https://timelordraps.github.io/verifier/reference.html) ·
[Report an ambiguity or counterexample](https://github.com/TimeLordRaps/verifier/issues/new/choose) ·
[Report a vulnerability privately](SECURITY.md)

## 30–60 second demonstration

```bash
git clone https://github.com/TimeLordRaps/verifier.git
cd verifier
python -m pip install .
vstd demo
```

The side-effect-free demo runs four public adversarial specimens:

```text
VSTD flagship adversarial demo
4/4 scenarios behaved as required.
[DEMO OK] Valid-looking proof, wrong artifact          → REJECTED
[DEMO OK] Bound exhausted without a false answer       → ACCEPTED/UNKNOWN
[DEMO OK] Inflated verification-cost claim             → REJECTED
[DEMO OK] Revoked ancestor behind valid descendants    → GRAPH-CANDIDATE-0
```

`[DEMO OK]` means the expected defensive outcome occurred; it is not a VSTD `PASS`.
The scenarios establish bounded behavior of this reference implementation over the
included specimens. They do not establish empirical truth, complete provenance,
external adoption, independent implementation, or general artificial intelligence (AI)
safety. Use `vstd demo --json` for JavaScript Object Notation (JSON) output or
`vstd demo --emit-specimens PATH` to inspect the generated files.

## What a result means

VSTD result terms remain tied to one exact proposition, mechanism, evidence set, and
bound:

| Result | Bounded meaning | It does not mean |
|---|---|---|
| `PASS` | The named mechanism established its declared proposition inside the stated coordinate and bounds. | The proposition is universally or permanently true. |
| `FAIL` | The mechanism found a checked violation, rejected certificate, or counterexample at the named surface. | Every broader interpretation is false. |
| `UNKNOWN` | Available evidence, capability, or resources did not establish `PASS` or `FAIL`. | False, safe, unsupported forever, or “probably PASS.” |
| `CONFLICTED` | Incompatible evidence or assertions remain explicit. | The conflict was resolved by choosing one side. |
| `NOT_ESTABLISHED` | The repository computes a candidate, but a required evidence-binding or conformance mechanism is absent. | Conformance, readiness, or a weak form of `PASS`. |

A VSTD `PASS` never means “true in the real world” without the exact real-world
proposition and observation boundary being part of the checked claim.

## Current maturity

This is the canonical repository status table. “Implemented” applies only to the named
reference surface; it does not imply adoption, external interoperability, certification,
or a second implementation.

| Surface | Normative status | Reference implementation | Evidence binding | Conformance status | Missing mechanism or evidence |
|---|---|---|---|---|---|
| VSTD-1 | Project specification with implemented reference subset | Claim receipts, checker reports, strict generic-run profile, inspection, and compatibility reads | Claim coordinates, stable digests, mechanism descriptors, and declared provenance; actor separation is not inferred | Implemented reference subset | External implementation and a validator binding distinct producer/checker actors and execution seams |
| VSTD-2 | Additive experimental project specification | Typed verification geometry, residuals, closure checks, schema, and tests | Geometry and declared reconstruction evidence inside the receipt | Implemented vertical slice | Independent implementation and broader geometry interoperability |
| VSTD-3 | Implemented project specification | Typed accelerator model, strict validator, emulator, offline adapters, continuity, fleet, and claim evaluation | Conditional on source-specific signatures, nonces, reference values, topology, events, and trust roots; host inventory remains weak evidence | Implemented reference surface | Vendor firmware integration, production trust roots, and complete-mediation evidence outside the emulator boundary |
| VSTD-4 | Project specification | A grounded decision certificate (GDC) parser/kernel plus structural depth candidate | The certificate binds formula, grounding, claim, roots, and bounds; rung references and VSTD-1/2/3 preconditions are not evidence-bound by the depth runtime | `NOT_ESTABLISHED` | Rung-by-rung evidence validation, lower-layer composition, and an independent checker implementation |
| VSTD-5 | Draft | Fail-closed rejection of current VSTD-4 candidates only | No witness-corroboration binding is implemented | Not implemented | Witness protocol, qualifying VSTD-4 input, distinct actors, independence evidence, and operational experience |
| VSTD-Graph-1 | Project specification with implemented reference subset | Content-addressed artifacts, transformations, conflicts, policy queries, receipts, and recorded reachability | Binds recorded objects and edges; it does not establish real-world completeness or causality | Implemented reference subset | Independent implementation and external provenance-profile interoperability |
| VSTD-Graph-2 | Project layer specification | Candidate bounded-collection level and ceiling-certificate computation | Uses caller-supplied object and edge ratings; the ratings are not validated against layer-2 evidence | `NOT_ESTABLISHED` | Rating-to-evidence validators for members, ancestors, statuses, and transformation edges |
| VSTD-Graph-3 | Project layer specification | Candidate accountable-provenance level and ceiling-certificate computation | Uses caller-supplied object and edge ratings; no mechanism establishes that VSTD-3 produced them | `NOT_ESTABLISHED` | VSTD-3 rating evidence for every member, reachable ancestor, and transformation edge |
| VSTD-Graph-4 | Project layer specification | Candidate refutable-transformation level and ceiling-certificate computation | Uses caller-supplied object and edge ratings; claimed refutability-closure records are not validated | `NOT_ESTABLISHED` | VSTD-4 rating evidence and validation of every reached refutability closure |
| VSTD-Graph-5 | Draft profile | Candidate level 5 can be computed from caller-supplied ratings | No independent-witness or rating-evidence binding | `NOT_ESTABLISHED` | Graph-2–4 evidence binding plus a corroborated verification-network protocol |
| Generic run | Frozen `VSTD-0.1` compatibility profile under VSTD-1 | Plan, execute, capture, inspect, strict shape/digest validation, and declared-output rerun | Captures command, source state, outputs, environment, and manifest declarations; generic validation is not native claim verification | `vstd4_conformance = NOT_EVALUATED` | Sandbox, generic external-evidence resolver, and actor/execution binder |
| Experimental workflow | Non-normative experimental profile 0.1 | Strict validator, verdict-neutral GitHub event projector, allocation records, and command-line interface (CLI) | Preserves native platform results and explicit horizons with `verification_effect = NONE` | No VSTD conformance claim | Independent consumer, additional platform adapter, and evidence for allocation optimality |
| Supply Chain Integrity, Transparency, and Trust (SCITT) interoperability | Experimental, non-normative application profile and crosswalk | Real local Concise Binary Object Representation (CBOR) plus CBOR Object Signing and Encryption (COSE) signatures/receipt, loss-declared adapter, and adjacent native-result composition | Binds the exact payload under emitted test keys and local policy; registration never establishes payload truth | VSTD-4 remains `NOT_ESTABLISHED` | Public Transparency Service, external implementation/interoperability result, and Internet Engineering Task Force (IETF) review |
| zero-identity/zero-knowledge (ZIZK) artifact-first trust | Governing VSTD architecture in `standard/LADDER.md` section 1.1; not a separate layer or profile | Artifact-bound claim/evidence/mechanism semantics, contextual actor/artifact roles, forward support, and reverse diagnostic Rust constraints | Existing mechanism-specific evidence only; identity, reputation, repetition, and topology add no assurance | Governing architectural invariant; not a separate VSTD conformance result | Event serialization, support-transfer algebra, Rust concentration/localization, complete trichotomy derivation, and maturation of specific optional proof backends |
| RISC Zero proof-carrying reference mechanism | Bounded non-normative mechanism example under the governing ZIZK architecture | Pinned prover/verifier source plus a tracked real receipt, public envelope, self-test result, and offline verification command | Authenticates one fixed hidden-witness predicate and expected image identifier; it does not establish the witness's external truth | Native proof verified; no VSTD receipt mapping | Complete VSTD trichotomy predicate, second build, external audit, and additional proof backends |

The authoritative implementation-to-specification map is
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Normative meaning remains under
[standard/](standard/).

## Why VSTD exists

Ordinary computational results often omit machine-readable answers to four questions:

1. **What exactly was claimed?** Subject, predicate, parameters, scope, and limits.
2. **Which evidence supports it?** Exact bytes, digests, mechanisms, provenance, and trust roots.
3. **Where does the verdict stop?** Explicit coordinates, exclusions, and resource bounds.
4. **How can it change?** Reproduction, counterexample, challenge, invalidation, and degradation rules.

VSTD packages that review boundary in receipts and provenance hypergraphs. The core
design rule is:

> No assurance is gained from storage location, field name, repetition, graph
> multiplicity, actor reputation, or propagation. Every increase must identify the
> verification mechanism that earned it.

## Architecture

<img src="docs/assets/vstd-overview.svg" alt="Verifier Standard object and graph verification layers, each requiring separate evidence" width="920">

Specification numbers identify verification depth, not software revisions. The object
axis evaluates one computational claim; the Graph axis evaluates a bounded collection
and its recorded transformations.

| Depth | Object axis | Graph axis |
|---:|---|---|
| 1 | Claim mechanics | Recorded lineage |
| 2 | Verification surface | Bounded collection surface |
| 3 | Substrate accountability | Accountable provenance closure |
| 4 | Refutability | Refutable transformation closure |
| 5 | Witness corroboration | Corroborated verification network |

A higher-layer result does **not** supply, imply, upgrade, or repair a lower-layer
result. Aggregate depth requires separate passing evidence for every preceding layer.

The same recorded development graph can carry bounded artifact support forward and
diagnostic Rust backward. Rust identifies ancestors worth examining; it does not prove
guilt, responsibility, causality, or automatic ancestor falsification. See
[the governing architecture](standard/LADDER.md#11-artifact-first-causal-orientation).

This is VSTD's **ZIZK artifact-first trust architecture**, not an optional research
profile. Zero identity means actor identity and reputation supply no assurance. Zero
knowledge means a claim may use a proof-carrying mechanism that hides bounded evidence
when that mechanism establishes its exact predicate; it does not make disclosure
mandatory or assumption-free. The runnable
[RISC Zero reference mechanism](examples/zizk_artifact_first/) is one bounded backend,
while its proof system and unfinished transfer mechanics remain mechanism-specific.

## Install and use

The distribution name is `verifier-standard`. The published base package has no
required third-party runtime dependencies.

```bash
python -m pip install verifier-standard  # latest published release
python -m pip install .                  # current release-candidate checkout
python -m pip install ".[yaml]"          # YAML Ain't Markup Language (YAML) manifests
python -m pip install ".[jsonschema]"    # JSON Schema validation
python -m pip install ".[scitt]"         # optional SCITT/COSE experiment
```

`vstd` is the canonical cross-platform CLI name. `verifier` remains a compatibility
alias but can resolve to Windows Driver Verifier. `verifiable` is a permanent legacy
alias because historical receipts may bind it in falsification instructions.

An unrelated PyPI distribution named `verifier` exports the same top-level Python
import. Do not co-install it with `verifier-standard`.

### Capture a generic computation

A manifest contains an executable command. `vstd run` does not sandbox it. Inspect the
plan first and execute only trusted manifests inside an appropriate operating-system or
container boundary.

```bash
vstd plan examples/generic_run/manifest.json --json
vstd run examples/generic_run/manifest.json --output /tmp/vstd-receipt
vstd validate /tmp/vstd-receipt
vstd inspect /tmp/vstd-receipt
vstd reproduce /tmp/vstd-receipt --rerun
```

Generic `validate` checks the strict profile shape and stable-payload digest. It does
not rehash external artifacts, resolve evidence references, rerun the command, or verify
the recorded declaration as a native domain claim. `reproduce --rerun` separately
executes the recorded command and compares declared output paths, digests, and execution
outcome. Matching outputs do not establish actor independence, environment equivalence,
semantic equivalence, or truth outside that scope.

### Use the Python application programming interface (API)

```python
from verifier.core.certificate import certificate_from_canonical_bytes
from verifier.core.kernel import check

certificate = certificate_from_canonical_bytes(certificate_bytes)
result = check(certificate, budget=verification_budget, binding=claim_binding)
```

The installed wheel contains byte-identical copies of every normative specification, so
a verifier descriptor can retain its exact specification binding outside a source
checkout. See the generated [CLI and API
reference](https://timelordraps.github.io/verifier/reference.html).

## Receipts, Graphs, and grounded certificates

- [VSTD-1 receipts](standard/VSTD-1.md) carry claim coordinates, evidence,
  checker results, trust boundaries, and reproducibility information.
- [VSTD-Graph-1](standard/VSTD-Graph-1.md) records content-addressed artifacts,
  many-to-many transformations, conflicts, and bounded downstream reachability.
- [`VSTD4-GDC-1`](standard/VSTD-4.md) binds a decision certificate to a formula,
  grounding, claim coordinate, verifier descriptor, roots, and resource bounds.

The grounded-certificate checker rejects over-budget headers before proof work, rejects
cost-tier inflation, validates grounding before the decision block, and preserves
`UNKNOWN` when a bound is exhausted. Kernel acceptance establishes only the bounded
certificate result; it is not VSTD-4 conformance, evidence authenticity, external
validation, or proof of the unobserved world.

## Interoperability

VSTD composes beside native systems rather than replacing them:

```text
native object ──native verifier──> native result
      └──── exact bytes + identity ──> loss-declared adapter
                                           └──> VSTD claim boundary
```

The experimental SCITT profile uses
real Concise Binary Object Representation (CBOR) and COSE
signatures and a local inclusion receipt. It demonstrates exact payload carriage and
adjacent verification under test keys. SCITT registration proves neither payload
correctness nor VSTD conformance. See the [crosswalk](docs/standards/VSTD_SCITT_CROSSWALK.md),
[semantic boundary](docs/standards/SCITT_SEMANTIC_BOUNDARY.md), and
[runnable example](examples/scitt_interop/).

The [ecosystem map](docs/ECOSYSTEM.md) separately covers adjacent provenance,
software-supply-chain, signing, and transparency systems without implying endorsement or
adoption.

## Specifications and navigation

Read authoritative material in this order:

1. [Ladder and composition](standard/LADDER.md)
2. [Object and Graph layer documents](standard/)
3. [Frozen wire identifiers](standard/WIRE_IDENTIFIERS.md)
4. [Published schemas](receipts/schema/)
5. [Implementation ownership](docs/ARCHITECTURE.md)
6. [Claims and limits](docs/CLAIMS_AND_LIMITS.md)

Additional entry points:

| Goal | Document |
|---|---|
| Install and exercise the first-run path | [Quickstart](docs/QUICKSTART.md) |
| Understand terminology and precedents | [Concepts and precedents](docs/CONCEPTS_AND_PRECEDENTS.md) |
| Inspect abbreviated terms | [Acronyms](docs/ACRONYMS.md) |
| Review experimental profiles | [Experiment index](experiments/INDEX.md) |
| Understand human claim traversal | [Human operating guide](HUMANS.md) |
| Inspect project direction and non-goals | [Roadmap](ROADMAP.md) |

## Reproducibility and releases

A release contains a canonical artifact set: ZIP archive format (ZIP), wheel, source
distribution, and external manifest bound to the exact public Git commit and file
members. The continuous integration (CI) workflow builds on Windows and Linux and rejects
cross-platform byte differences. GitHub
artifact attestations bind uploaded bytes to the workflow; they do not establish source
correctness, tag identity, or adoption.

```bash
gh attestation verify PATH_TO_DOWNLOADED_ASSET --repo TimeLordRaps/verifier
```

Use [RELEASING.md](RELEASING.md) to verify the manifest, tag, artifact attestations,
package name, and historical compatibility. The current checkout is an unreleased
1.2.0 candidate; use the [latest release page](https://github.com/TimeLordRaps/verifier/releases/latest)
for published citation and artifact coordinates.

## Claims, security, and contribution

Review [claims and limits](docs/CLAIMS_AND_LIMITS.md) before publishing a VSTD result.
The reference implementation may improve auditability, reproducibility, incident
analysis, and challenge routing over observable records. It cannot prove general AI
safety, reveal hidden model state, establish physical-world completeness, or compensate
for missing instrumentation.

`vstd run` executes manifest commands without sandboxing. See the
[security policy](SECURITY.md) and use GitHub private vulnerability reporting for
sensitive findings.

Contributors should start with [CONTRIBUTING.md](CONTRIBUTING.md), which identifies
normative, implementation, schema, adapter, test, compatibility, and release pathways.
Use the issue forms for a
[specification ambiguity](https://github.com/TimeLordRaps/verifier/issues/new?template=specification-ambiguity.yml),
[counterexample](https://github.com/TimeLordRaps/verifier/issues/new?template=counterexample.yml),
or [implementation/interoperability report](https://github.com/TimeLordRaps/verifier/issues/new?template=implementation-report.yml).

Project authority and centralization are documented in [GOVERNANCE.md](GOVERNANCE.md).
Automated-contributor rules live in [AGENTS.md](AGENTS.md); the human operating model in
[HUMANS.md](HUMANS.md); and live repository contradictions only in [TIME.md](TIME.md).

## Citation and license

Cite a published release from its versioned GitHub release metadata or
`CITATION.cff` at that tagged coordinate. Do not cite unreleased candidate metadata as
a published release.

Licensed under the [Apache License 2.0](LICENSE); see [NOTICE](NOTICE). VSTD is not
affiliated with or endorsed by the Apache Software Foundation.
