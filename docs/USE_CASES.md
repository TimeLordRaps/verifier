# Typical use cases

> **Acronyms:** application programming interface (API); command-line interface (CLI);
> continuous integration (CI); machine learning (ML); operating system (OS).

Each section below states a situation, names the Verifier Standard (VSTD) mechanism that
addresses it, points at a runnable example, and says plainly what the mechanism leaves
unestablished. The last section lists situations VSTD does **not** address, which is the
more useful half for deciding whether to adopt it.

Every path named here is executable from a checkout of the
[released reference](INSTALLATION.md).

## 1. Publishing a benchmark number somebody else can check

**Situation.** You report a score. A reader wants to know what exactly was measured, on
which inputs, with which command, and what would make the number wrong.

**Mechanism.** A generic-run receipt binds the declared command, inputs, outputs, claim
scope, limitations, and falsification conditions, then digests the stable payload so any
later edit is detectable.

```bash
vstd plan examples/generic_run/manifest.json --json
vstd run examples/generic_run/manifest.json --output receipt-demo
vstd validate receipt-demo
```

Planning is side-effect free; `run` executes the manifest command and is not a sandbox.
Full walkthrough: [Your first receipt](FIRST_RECEIPT.md).

**Leaves open.** That the number is correct, that the computation was appropriate, or that
anybody else observed it. Validation checks structure and recomputes the digest; it does
not rehash declared artifacts or evaluate the claim.

## 2. Proving a result set has not drifted since you published it

**Situation.** You shipped a directory of outputs months ago. You need to show a
collaborator, an auditor, or your future self that the copy in hand is the same bytes.

**Mechanism.** Artifact control: freeze exact bytes into a guarded bundle, seal it with an
Ed25519 key, thaw a working copy, and check the descendant against the sealed parent. The
runtime reports `THAWED_DIRTY` and exits `1` the moment a byte differs.

Full walkthrough including the failure branches:
[Seal an artifact and detect a change](tutorials/SEAL_AN_ARTIFACT.md).

**Leaves open.** That the frozen bytes are correct, that the key belongs to a particular
person or organization, and that the freeze happened when it claims to. A seal establishes
internal consistency; supply `--expected-artifact-id` from an independent source to detect
substitution of the whole bundle.

## 3. Checking that a result holds across operating systems

**Situation.** A test passes on your machine and in CI on Linux. You need to know whether
the Windows and macOS runs actually produced the same declared results, or merely also
exited zero.

**Mechanism.** `compare_platform_run_receipts` compares declared result surfaces across
canonically intact run receipts.

```python
from verifier import compare_platform_run_receipts

result = compare_platform_run_receipts(["receipt-linux/receipt.json", "receipt-windows/receipt.json"])
result.status
```

`PASS` requires complete declared platform coverage, canonical integrity, equal
non-platform bindings, and equal declared result projections. `CONFLICTED`,
`NOT_ESTABLISHED`, and `INVALID` stay separate, so "the platforms disagree" never gets
filed as "we did not check".

**Leaves open.** Everything outside the declared result projection. The returned object is
a diagnostic, not a receipt and not a conformance result.

## 4. Finding out what your verification story is actually missing

**Situation.** You have tests, a review process, and some monitoring, and you suspect the
combination has gaps — but "we should test more" is not a plan.

**Mechanism.** Model the surface as a VSTD-2 geometry, then derive structured holes from
it. Each hole is typed, has a source, and carries separate flags for whether it blocks
ordinary closure and whether it blocks self-closure.

```bash
python examples/interoperability_planning/demo.py
```

That example models one small question — whether a grocery list is in Python's default
lexicographic string order — detects holes in the geometry, and matches them against a
checker descriptor. It reports `hole_count: 5`, `unmatched_hole_count: 3`,
`ordinary_closed: false`, `self_closed: false`, `checker_invocations: 0`, and
`execution_performed: false`. Planning does not run anything.

The smallest geometry slice on its own is
[`examples/verification_geometry_residual/`](../examples/verification_geometry_residual/README.md).
API details: [Python API guide](PYTHON_API_GUIDE.md#analyze-a-verification-geometry).

**Leaves open.** Everything outside the model you supplied. The analysis is deterministic
over the modeled surface; it does not infer obligations you did not write down, and a
closed model is not a safe system.

## 5. Recording dataset and model lineage that survives a challenge

**Situation.** An ML artifact's provenance matters — which datasets, which transformations,
which upstream models — and a downstream consumer may later dispute part of it.

**Mechanism.** `ProvenanceHypergraph` records n-ary lineage; `establish_graph_level` reruns
rating mechanisms before computing a conforming Graph profile rather than trusting recorded
ratings; `AssuranceLedger` keeps an append-only current-state overlay so later findings do
not rewrite history. The portable-record pair lets another party rebuild the evidence store
and replay every rating offline.

```bash
python examples/graph_topology/demo.py
```

**Leaves open.** That the recorded lineage is complete or honest. The graph is a
declaration; the evidence-bound establishment path is what makes a rating rerunnable, and
compatibility candidate computations remain `NOT_ESTABLISHED`.

## 6. Accepting evidence from a party you do not fully trust

**Situation.** A vendor, a contractor, or an upstream project hands you results. You want
to rerun their check rather than accept their conclusion, and you want a bounded amount of
work doing it.

**Mechanism.** A `BoundProposition` names the subject, expected value, mechanism, mechanism
digest, evidence references, trust roots, and resource ceilings. A `VerificationSession`
reruns only mechanisms you explicitly registered, resolves evidence from a content-addressed
store, and enforces the bounds *before* invoking anything.

The distinction that matters: an unregistered mechanism, an absent evidence item, and an
over-budget input each return `UNKNOWN` — never `FAIL`, and never a silent `PASS`. See
[the four non-PASS paths](PYTHON_API_GUIDE.md#four-ways-this-returns-something-other-than-pass).

**Leaves open.** Whether the mechanism itself is apt for the claim, and anything the trust
roots were wrong about. VSTD does not decide whether an actor is reputable.

## 7. Interoperating with an existing transparency or proof system

**Situation.** You already use a signing, transparency-log, or proof format, and you want
VSTD records to sit alongside it rather than replace it.

**Mechanism.** The interoperability surface treats those systems as external evidence with
declared boundaries rather than absorbing them.

- [`examples/scitt_interop/`](../examples/scitt_interop/README.md) — Supply Chain
  Integrity, Transparency, and Trust (SCITT) cryptographic interoperability.
- [`examples/interoperability_compositions/`](../examples/interoperability_compositions/README.md)
  — bounded compositions over external checkers.
- [`examples/zizk_artifact_first/`](../examples/zizk_artifact_first/README.md) — artifact-first
  reference surfaces, including a reduced instruction set computer (RISC) Zero
  zero-knowledge path.
- [`examples/experimental_workflow/`](../examples/experimental_workflow/README.md) — a
  normalized platform snapshot in which all five records stay platform observations with
  `verification_effect = "NONE"`.

**Leaves open.** VSTD does not replace native domain verifiers, proof systems, signatures,
identity systems, transparency logs, or provenance formats. A platform observation — a
green workflow, a merged pull request — is recorded as an observation and grants no verdict.

## 8. Distributing a complete, rebuildable record of a body of work

**Situation.** You want to publish not one artifact but a snapshot: the measurements, the
mechanism, the derived results, and an explicit statement of what is still open — such that
another party can rebuild the whole thing byte for byte.

**Mechanism.** A publisher silo. The commit manifest forces you to declare a completeness
denominator, which artifacts are ground, what derives from what, what you excluded, and
what obligations remain. The assessment then reports six independent axes and will happily
tell you the snapshot is `INCOMPLETE` with a closed, valid signature.

Full walkthrough: [Publish a verification-artifact silo](tutorials/PUBLISH_A_SILO.md).
Wire-level specimen for another runtime:
[`examples/artifact-network/`](../examples/artifact-network/README.md).

**Leaves open.** The artifact-network surface is **experimental**; its wire identifiers
carry `0.1` schema versions and may change. Publisher identity is key-derived and says
nothing about real-world identity.

## 9. Retaining a component catalog and its source snapshot

**Situation.** You need the tooling that produced a result to still be inspectable later,
without depending on a package index staying up.

**Mechanism.** The experimental stored-component format retains a catalog and a bounded
public source snapshot without running any of it.

```bash
python examples/stored_components/build_reference_package.py --output reference-components.json --package-version 1.4.0
vstd components inspect reference-components.json --json
```

**Leaves open.** This is an instructional path for the
[stored format](COMPONENT_PACKAGES.md), not a hosted hub and not an installable package.

## 10. Explaining the idea to somebody in under a minute

**Situation.** A colleague asks what this is for and will not read a specification.

**Mechanism.** The flagship demo is four adversarial specimens rather than a happy path:

```bash
vstd demo
```

It reports `4/4 scenarios behaved as required`. Two scenarios succeed precisely because a
malformed certificate is rejected, one because `UNKNOWN` is preserved rather than resolved,
and one because a graph claim is capped. The label is `[DEMO OK]` rather than `[PASS]` for
exactly that reason.

## What VSTD does not do

| You want | VSTD is the wrong tool because |
|---|---|
| to know whether a vendor is trustworthy | it evaluates bounded propositions about computational processes, not actors |
| a sandbox for untrusted code | `run` executes the declared command; use OS or container isolation |
| to prove a claim is true | it binds claims to evidence and mechanisms; the claim's truth is a separate question |
| encryption or confidentiality | sealing is authentication and closure; bundle contents stay readable |
| a compliance certification | no accreditation, independent implementation, or external adoption is claimed |
| identity or key management | publisher and seal identities are key-derived and bind to no real-world identity |
| to make a weak result stronger by storing it | translating or storing a result never strengthens it |

The surface-by-surface boundary is in [claims and limits](CLAIMS_AND_LIMITS.md), and the
maturity of each path is in the
[current maturity table](../README.md#current-maturity). Some compatibility paths remain
`NOT_ESTABLISHED` on purpose.

## Where to go next

- [60-second quickstart](QUICKSTART.md)
- [Your first receipt](FIRST_RECEIPT.md)
- [Seal an artifact and detect a change](tutorials/SEAL_AN_ARTIFACT.md)
- [Publish a verification-artifact silo](tutorials/PUBLISH_A_SILO.md)
- [Python API guide](PYTHON_API_GUIDE.md)
- [Repository walkthrough](REPOSITORY_WALKTHROUGH.md)
