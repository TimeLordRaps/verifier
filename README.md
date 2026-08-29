<div align="center">

# Verifier Standard (VSTD)

**Portable, bounded, refutable evidence for computational claims.**

[![Repository checks](https://github.com/TimeLordRaps/verifier/actions/workflows/ci.yml/badge.svg)](https://github.com/TimeLordRaps/verifier/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/TimeLordRaps/verifier?display_name=tag&sort=semver)](https://github.com/TimeLordRaps/verifier/releases/latest)
[![Python 3.10–3.13](https://img.shields.io/badge/python-3.10%E2%80%933.13-3776AB.svg)](https://www.python.org/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-2f7d6d.svg)](LICENSE)
[![Status: alpha](https://img.shields.io/badge/status-alpha-d97706.svg)](#current-maturity)

</div>

> **Acronyms used below:** identifier (ID); reduced instruction set computer (RISC).

VSTD is a verification-domain language and Python reference implementation for packaging
bounded computational claims with their evidence, checking mechanisms, limits,
refutation conditions, provenance, and reproducibility information. It does **not**
replace native domain verifiers, proof systems, signatures, identity systems,
transparency logs, or provenance formats, and it never strengthens their results merely
by translating or storing them.

VSTD evaluates bounded validity propositions about computational processes represented by
software and evidence-bearing artifacts. It does not decide whether an actor is good, bad,
reputable, or trustworthy; identity and reputation alone contribute no verdict weight.

It addresses a practical review problem: a final answer or green check rarely says
exactly what was checked, which evidence was used, where the conclusion stops, or what
would overturn it. VSTD carries those boundaries with the result.

**Current boundary:** implemented reference paths cover receipts, generic computation
capture, provenance graphs, verification geometry, accelerator evidence, grounded
certificate checking, evidence-bound VSTD-4/VSTD-5 assessment, evidence-bound Graph
ratings, replayable additive Graph lifecycle/assurance propagation, reproduction, exact-byte artifact
freezing, finite self-closing seals, copy-on-write thawing, and a flagship adversarial demo.
Compatibility candidate paths remain `NOT_ESTABLISHED`; evidence-bound paths rerun exact
registered mechanisms and preserve their evidence, trust roots, bounds, and limitations.
No real external witness or independent implementation is claimed. See [current maturity](#current-maturity) and
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
| `NOT_ESTABLISHED` | The evaluated path did not establish conformance: it may be a compatibility candidate, or required evidence, exact binding, mechanism availability, mechanism result, prerequisite, or profile floor was missing or non-passing. | Conformance, readiness, or a weak form of `PASS`. |

A VSTD `PASS` never means “true in the real world” without the exact real-world
proposition and observation boundary being part of the checked claim.

## Current maturity

This is the canonical repository status table. “Implemented” applies only to the named
reference surface; it does not imply adoption, external interoperability, certification,
or a second implementation.

| Surface | Normative status | Reference implementation | Evidence binding | Conformance status | Missing mechanism or evidence |
|---|---|---|---|---|---|
| VSTD-1 | Project specification with implemented reference subset | Claim receipts, checker reports, strict generic-run profile, inspection, and current-profile reads | Claim coordinates, stable digests, mechanism descriptors, and declared provenance; actor separation is not inferred | Implemented reference subset | External implementation and a validator binding distinct producer/checker actors and execution seams |
| VSTD-2 | Additive experimental project specification | Typed verification geometry, residuals, closure checks, schema, and tests | Geometry and declared reconstruction evidence inside the receipt | Implemented vertical slice | Independent implementation and broader geometry interoperability |
| VSTD-3 | Implemented project specification | Typed accelerator model, strict validator, emulator, offline adapters, continuity, fleet, and claim evaluation | Conditional on source-specific signatures, nonces, reference values, topology, events, and trust roots; host inventory remains weak evidence | Implemented reference surface | Vendor firmware integration, production trust roots, and complete-mediation evidence outside the emulator boundary |
| VSTD-4 | Project specification with implemented reference paths | grounded decision certificate (GDC) parser/kernel, compatibility candidate depth, and evidence-bound establishment/recheck | Exact VSTD-1/2/3 and fourteen-rung propositions, content-addressed evidence bytes, mechanism implementation digests, trust roots, and bounds | Candidate path `NOT_ESTABLISHED`; evidence-bound path can establish conformance | Independent implementation, external interoperability, and deployment-specific rung mechanisms/evidence |
| VSTD-5 | Project specification with implemented reference mechanism | Evidence-bound entry gate, seven separation dimensions, exact admitted-certificate binding, corroboration checks, duplicate refusal, disagreement preservation, receipt build/recheck | Witness coordinate, exact negative separation propositions, VSTD-4 commitment/certificate, checker, observations, mechanisms, trust roots, bounds, and embedded evidence | Mechanism can establish a bounded result; a positive observation with unresolved independence remains overall `UNKNOWN`; no repository claim of a real independent witness | Real independent witnesses, second implementation, external attack, and operational interoperability |
| VSTD-Graph-1 | Project specification with implemented reference subset | Content-addressed artifacts, transformations, conflicts, policy queries, receipts, and recorded reachability | Binds recorded objects and edges; it does not establish real-world completeness or causality | Implemented reference subset | Independent implementation and external provenance-profile interoperability |
| VSTD-Graph-2 | Project specification with implemented reference paths | Compatibility candidate plus evidence-bound Bounded Collection Surface computation/recheck | Registered mechanisms rerun exact member, ancestor, and edge ratings bound to the Graph bytes, deduplicated members, collection, and claim | Candidate `NOT_ESTABLISHED`; evidence-bound profile 1–5 path can establish; profile zero cannot | External rating mechanisms, independent implementation, and interoperability |
| VSTD-Graph-3 | Project specification with implemented reference paths | Compatibility candidate plus evidence-bound Accountable Provenance Closure computation/recheck | Same complete closure binding, including VSTD-3 rating propositions | Candidate `NOT_ESTABLISHED`; evidence-bound path can establish | Production VSTD-3 rating evidence across a real collection |
| VSTD-Graph-4 | Project specification with implemented reference paths | Compatibility candidate plus evidence-bound Refutable Transformation Closure computation/recheck | Same complete closure binding; an edge mechanism must actually check its refutability closure | Candidate `NOT_ESTABLISHED`; evidence-bound path can establish | External closure mechanisms and independent replay |
| VSTD-Graph-5 | Project specification with implemented reference paths | Compatibility candidate plus evidence-bound Corroborated Verification Network computation/recheck | Exact VSTD-5 object and transformation rating mechanisms across the complete closure | Candidate `NOT_ESTABLISHED`; evidence-bound path can establish | Real independently corroborated collection, second implementation, and interoperability |
| Generic run | VSTD-1 generic-computation profile | Plan, execute, capture, inspect, strict shape/digest validation, and declared-output rerun | Captures command, source state, outputs, environment, and manifest declarations; generic validation is not native claim verification or VSTD-4 conformance | Implemented VSTD-1 profile | Sandbox, generic external-evidence resolver, and actor/execution binder |
| Artifact freeze, seal, and thaw | Normative artifact-control mechanism; not a numbered VSTD or receipt profile | Exact regular-file byte preservation, dual-digest artifact identity, read-only guards, finite self-closing Ed25519 seals, external anchor checks, and copy-on-write thaw status | Binds artifact bytes, paths, media type, freeze manifest, carried key, signature, and optional expected artifact/key coordinates | Implemented mechanism version 1 | Durable external archive, privileged-write prevention, trusted time, encryption, semantic correctness, and realm/continuity verification |
| Experimental workflow | Non-normative experimental profile 0.1 | Strict validator, verdict-neutral GitHub event projector, allocation records, and command-line interface (CLI) | Preserves native platform results and explicit horizons with `verification_effect = NONE` | No VSTD conformance claim | Independent consumer, additional platform adapter, and evidence for allocation optimality |
| Supply Chain Integrity, Transparency, and Trust (SCITT) interoperability | Experimental, non-normative application profile and crosswalk | Real local Concise Binary Object Representation (CBOR) plus CBOR Object Signing and Encryption (COSE) signatures/receipt, loss-declared adapter, and adjacent native-result composition | Binds the exact payload under emitted test keys and local policy; registration never establishes payload truth | VSTD-4 remains `NOT_ESTABLISHED` | Public Transparency Service, external implementation/interoperability result, and Internet Engineering Task Force (IETF) review |
| zero-identity/zero-knowledge (ZIZK) artifact-first TRUST | Governing VSTD architecture in `standard/LADDER.md` section 1.1; not a separate numbered profile | Hash-chained event serialization and offline replay, evidence-bound forward TRUST, typed ROT, challenge projection, reverse RUST, structural concentration, conflict resolution, explicit localization, and bounded diagnostic attribution | Exact Graph topology, proposition bindings, embedded evidence bytes, mechanisms, trust roots, bounds, and immutable history | Implemented reference mechanism; no universal support score or actor trust | Domain-specific transfer/localization mechanisms, independent cross-implementation replay, complete trichotomy derivation, and maturation of optional proof backends |
| RISC Zero proof-carrying reference mechanism | Bounded non-normative mechanism example under the governing ZIZK architecture | Pinned prover/verifier source plus a tracked real receipt, public envelope, self-test result, and verifier command that can run network-offline after setup | Authenticates one fixed hidden-witness predicate and expected image identifier; it does not establish the witness's external truth | Native proof verified; no VSTD receipt mapping | Complete VSTD trichotomy predicate, second build, external audit, and additional proof backends |

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

<img src="docs/assets/vstd-overview.svg" alt="Verifier Standard object and Graph numbered profiles, each requiring separate evidence for its closure coordinate" width="920">

VSTD is a verification complex of named closure coordinates and evidence-bearing
relations. Specification numbers select cumulative profiles, not software revisions,
interchangeable layers, or scalar assurance levels. The object axis evaluates one
computational claim; the Graph axis evaluates a bounded collection and its recorded
transformations.

| Profile number | Object closure coordinate | Graph closure coordinate |
|---:|---|---|
| 1 | Claim mechanics | Recorded lineage |
| 2 | Verification surface | Bounded collection surface |
| 3 | Substrate accountability | Accountable provenance closure |
| 4 | Refutability | Refutable transformation closure |
| 5 | Witness corroboration | Corroborated verification network |

A later-profile result does **not** supply, imply, upgrade, or repair a prerequisite
coordinate. Object profile depth requires separate passing evidence for every required
coordinate.

As an operational traversal, an implementation may capture a run through VSTD-1, map
profiler or domain observations through adjacent adapters into a VSTD-2 surface, bind the
execution substrate through VSTD-3, make the result portably refutable through VSTD-4, and
record independently evidenced witness corroboration through VSTD-5. This traversal does
not collapse the named coordinates. VSTD-Graph is the orthogonal collection axis: a bounded Graph result
may be materialized as a content-addressed artifact and enter a later verification loop only
with its source graph, selected surface, mechanism, lineage, losses, limitations, conflicts,
and current admissibility preserved. The compatibility `graph_level` result remains a
`NOT_ESTABLISHED` candidate. `establish_graph_level` can establish only profile 1–5 after
every required rating mechanism is rerun from exact evidence bound to the exact Graph,
member set, collection, and claim. Profile zero remains `NOT_ESTABLISHED`.

The formal names **TRUST**, **ROT**, and **RUST** are semantic terms, not acronyms, actor
ratings, scalar scores, numbered-profile verdicts, or references to the Rust programming language.
They serialize only as typed events in `VSTD-GRAPH-ASSURANCE-1`.
TRUST is mechanism-earned artifact support moving forward edge by edge through checked
development, with each event binding one exact transformation, its inputs and output, the
historical Graph digest, and any prerequisite TRUST events;
ROT is typed, time-indexed degradation of current admissibility without rewriting
historical evidence; RUST is the inverse-TRUST diagnostic mechanic moving backward from a
descendant deviation toward recorded ancestor candidates. This memetic propagation does
not by itself prove guilt, responsibility, falsehood, causal localization, or automatic
ancestor falsification. The reference runtime requires a separate passing localization
mechanism bound to one exact passing RUST event and descendant-deviation proposition before
it can emit a bounded
`BLAME` or `GUILT`. BLAME establishes bounded responsibility or material contribution;
GUILT is not its opposite, but the stronger combined result that additionally establishes
an exact violated obligation. Neither result concerns actor character. See [the governing
architecture](standard/LADDER.md#11-artifact-first-causal-provenance-orientation).

`VSTD-GRAPH-ASSURANCE-1` carries the immutable historical Graph, exact event bindings,
embedded evidence bytes, event hash chain, and derived current-view digest.
`recheck_assurance_log` rehashes the evidence, reruns each exact registered mechanism, and
rejects any event or current view that does not reproduce. Conflict adjudication and current
admissibility are separate: a selected status affects the current artifact or transformation
state, while resolving an arbitrary predicate cannot silently restore TRUST.

This is VSTD's **ZIZK artifact-first TRUST architecture**, not an optional research
profile. Zero identity means zero identity-derived verdict weight, not anonymity or the
absence of identifiers. Zero knowledge means zero unevidenced knowledge is presumed: a
proposition remains `UNKNOWN` until a named mechanism earns a bounded result. When a
witness must remain confidential, cryptographic zero knowledge can enclose that
architectural rule by binding the exact program, predicate, public commitments, output,
proof parameters, and verifier without attaching TRUST to the prover's identity. Only a
named proof system can earn that privacy property; a digest or hidden input cannot. The
runnable
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
python -m pip install ".[seal]"          # optional Ed25519 artifact sealing
python -m pip install ".[scitt]"         # optional SCITT/COSE experiment
```

`vstd` is the canonical cross-platform CLI name. `verifier` remains a compatibility
alias but can resolve to Windows Driver Verifier. `verifiable` is a permanent legacy
alias because historical receipts may bind it in falsification instructions.

An unrelated PyPI distribution named `verifier` exports the same top-level Python
import. Do not co-install it with `verifier-standard`.

### Freeze, seal, verify, and thaw an artifact

Freezing preserves exact regular-file bytes and portable paths. Sealing is a separate,
readable authentication and closure action; it is **not encryption**. Generate an
Ed25519 key with a suitable local key tool, then run:

```bash
openssl genpkey -algorithm Ed25519 -out ed25519-private.pem
vstd artifact freeze PATH ARTIFACT.vstd --media-type application/octet-stream
vstd artifact verify ARTIFACT.vstd --freeze-only
vstd artifact seal ARTIFACT.vstd --private-key ed25519-private.pem
vstd artifact verify ARTIFACT.vstd --expected-artifact-id EXPECTED_ID
vstd artifact thaw ARTIFACT.vstd MUTABLE_COPY
vstd artifact status MUTABLE_COPY
```

The finite seal signs the complete envelope with its signature and identifier fields
explicitly empty, then derives the seal identifier over the signature-bearing envelope
with only its identifier empty. Verification recomputes both projections, avoiding an
infinite seal-of-seal regress. The carried public key establishes internal consistency;
an expected artifact identifier, expected key identifier, or separately verified
manifest/log coordinate is still required to detect whole-bundle substitution.

A freeze or seal establishes bounded integrity and closure only—not correctness,
freshness, ownership, authorization, trusted time, external preservation, or actor trust.
Thaw is copy-on-write: it creates a mutable descendant and leaves the sealed parent
unchanged. See the normative
[artifact-control mechanism](standard/ARTIFACT_CONTROL.md) and the architectural
[realm/time-capsule model](docs/REALMS_AND_TIME_CAPSULES.md).

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
from pathlib import Path

from verifier.core.run import describe_run_plan, load_manifest

manifest_path = Path("examples/generic_run/manifest.json")
manifest = load_manifest(manifest_path)
plan = describe_run_plan(manifest, manifest_path.parent)
print(plan["command"], plan["executes_without_sandbox"])
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

1. [Verification complex, terminology, and profile composition](standard/LADDER.md)
2. [Object and Graph numbered-profile documents](standard/)
3. [Serialized receipt identifiers](standard/WIRE_IDENTIFIERS.md)
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
