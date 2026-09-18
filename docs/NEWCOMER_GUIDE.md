# Newcomer Guide: Verification from Scratch

> **Acronyms used below:** application programming interface (API); artificial intelligence (AI); Boolean satisfiability problem (SAT); central processing unit (CPU); command-line interface (CLI); conjunctive normal form (CNF); deletion resolution asymmetric tautology (DRAT); directed acyclic graph (DAG); grounded decision certificate (GDC); identifier (ID); intermediate representation (IR); JavaScript Object Notation (JSON); linear resolution asymmetric tautology (LRAT); machine learning (ML); nondeterministic polynomial time (NP); operating system (OS); reduced instruction set computer (RISC); satisfiability modulo theories (SMT); Secure Hash Algorithm 256-bit (SHA-256); unsatisfiable (UNSAT); Verifier Standard (VSTD).

Welcome to Verifier Standard (VSTD). If you are new to formal verification, proof systems, or computational reproducibility, this guide is designed for you. Whether you are a high school student, an undergraduate taking your first data structures course, a compiler developer, an AI safety researcher, or a SAT solver expert, this guide introduces the core concepts and gets you running code in five minutes.

---

## 1. The 30-second intuition: grocery receipts vs. green checkmarks

When you write software or run experiments today, tools usually give you a single bit of feedback: a green checkmark (`PASS`) or a red cross (`FAIL`).

Imagine going to the grocery store, handing over your card, and the cashier says: *"Payment complete, trust me."* You would ask:
- *Which items were scanned?*
- *What was the unit price of each item?*
- *What store, date, and cash register processed this?*
- *If there is an overcharge on line 4, how can I dispute that exact item?*

You expect an **itemized receipt** that binds the transaction to the exact items, register, and timestamp.

In scientific computing, machine learning, and software engineering, a green checkmark does not tell you:
1. **What exact file or dataset was checked?** (Did someone swap the weights or modify the dataset after the run?)
2. **What tool did the checking, and what were its bounds?** (Did it run out of time and exit 0 by mistake?)
3. **Can another person reproduce the exact same bytes on their machine?** (Or does it only work on the author's laptop?)
4. **How can someone prove the result wrong?** (What is the refutation recipe?)

**VSTD is the itemized receipt for computational claims.**

It wraps any computation with five cryptographic guarantees:
```text
claim + exact evidence + named mechanism + bounds + refutation recipe
                          │
                          ▼
                PASS / FAIL / UNKNOWN
```

---

## 2. Why "UNKNOWN" is your friend

In standard tools, everything is forced into a binary: either it passed or it failed. If a test times out, a script crashes, or a theorem prover runs out of memory, systems often silently fail or crash.

In honest science, if your thermometer only measures up to 100°C and your reaction reaches 150°C, you do not write down *"Reaction passed."* You write down: **inconclusive / out of bounds**.

VSTD elevates `UNKNOWN` to a first-class, honorable result:
- `PASS`: The specific tool checked the specific claim over the specific files within stated resource bounds, and confirmed it.
- `FAIL`: The tool found a counterexample or proven violation.
- `UNKNOWN`: The tool ran out of time, memory, or evidence before reaching a conclusion. **VSTD refuses to guess.**

---

## 3. Five-minute Python walkthrough

You do not need complicated tools or heavy frameworks to use VSTD. The reference library has **zero required third-party dependencies**—it runs on standard Python 3.10+.

### Step 1: Install `verifier-standard`

```bash
python -m pip install "verifier-standard==1.5.0"
```

### Step 2: Inspect the library

Open a Python interactive shell:

```python
import verifier

print(verifier.__version__)
# '1.5.0'

print(verifier.__standard__)
# 'VSTD-5'
```

### Step 3: Run the built-in defensive demonstration

To see VSTD catch real-world defects without modifying any files on your computer, run the canonical cross-platform command:

```bash
vstd demo
```

You will see four defensive scenarios:
1. **Valid-looking proof, wrong artifact (`REJECTED`)**: An attacker provides a real mathematical proof, but binds it to the wrong data file. VSTD computes the SHA-256 hash and catches the mismatch immediately.
2. **Bound exhausted without a false answer (`ACCEPTED/UNKNOWN`)**: A calculation hits its resource limit. Instead of faking a pass, VSTD honestly outputs `UNKNOWN`.
3. **Inflated verification-cost claim (`REJECTED`)**: A script claims a verification step cost \$1,000,000 of compute when it only took milliseconds. The receipt refuses the ungrounded cost claim.
4. **Revoked ancestor behind valid descendants (`GRAPH-CANDIDATE-0`)**: A computation looks valid, but one of its upstream dependencies was revoked. VSTD traces the lineage graph and flags the compromised ancestor.

---

## 4. Seven domain lenses: how VSTD fits your field

VSTD is domain-agnostic: it does not replace your native tools; it packages and standardizes their evidence boundaries. Here is how people in different fields use it, with concrete links to tutorials and runnable examples:

### A. For Undergraduates, High Schoolers & Self-Taught Programmers
Think of VSTD as a **tamper-proof digital lab notebook**. When submitting a class project, physics simulation, or machine learning experiment:
- You hash your dataset, source code, and output graphs.
- You record the exact Python version, command arguments, and operating system.
- Anyone grading or evaluating your work can verify with one command that your results were generated by that exact code on that exact data.

#### How can a grader possibly verify your work with one command?
If you have ever handed in homework, you might wonder: *How can a teacher or automated grading bot actually know my code really produced this graph without reading every single line or trusting my word?*

Here is the exact three-step mechanic:
1. **Digital Fingerprints (SHA-256 Hashes)**: VSTD computes cryptographic fingerprints of your code (`script.py`) and inputs (`data.csv`). If anyone edits a single character or changes one number in the comma-separated values (CSV), the fingerprint changes completely into a different, unpredictable hex string.
2. **The Receipt Binding**: When you run `vstd run manifest.json --output my_receipt`, VSTD executes your script, records the exact command, exit code, and runtime platform details (e.g. Python version and OS architecture, without recording private host environment variables or credentials), and takes fingerprints of the output files (e.g. `plot.png` has digest `e3b0c442...`).
3. **The Grader's Single Command (`vstd reproduce`)**: The grader downloads your receipt and runs:
   ```bash
   vstd reproduce my_receipt/
   ```
   Under the hood, `vstd reproduce`:
   - Checks that the inputs match the fingerprints in your receipt.
   - Creates a clean, temporary execution folder and re-runs `python script.py data.csv`.
   - Fingerprints the newly generated plot file and compares: *Does the fresh digest match `e3b0c442...` byte-for-byte?*
   - If they match, the grader sees: `[REPRODUCE OK] 100% byte-for-byte identical output`. If a student edited the graph in Photoshop or faked the numbers, the newly computed bytes will not match, and VSTD outputs `REJECTED: output digest mismatch`.

- **Tutorial & Runnable Specimen**: Follow the full step-by-step walkthrough in [Your First Receipt](FIRST_RECEIPT.md) and inspect the runnable specimen in [`examples/generic_run/`](../examples/generic_run/manifest.json).

### B. For Boolean Satisfiability (SAT) and Satisfiability Modulo Theories (SMT) Solver Enthusiasts
Modern SAT and SMT solvers decide whether a propositional logic formula is satisfiable (`SAT`) or unsatisfiable (`UNSAT`). But solver implementations are complex and can have soundness bugs:
- For `SAT`, the solver produces a truth assignment that is trivially checkable in linear time.
- For `UNSAT`, high-assurance solvers emit clausal proof certificates, such as deletion resolution asymmetric tautology (DRAT) or linear resolution asymmetric tautology (LRAT) format traces.
- VSTD wraps the conjunctive normal form (CNF) formula digest, certificate file digest, certificate checker binary, and CPU runtime bounds into a standard JSON receipt. Third parties can verify the refutation certificate without repeating the NP-hard search.
- **Tutorial & Runnable Specimen**: Read about clausal certificates in [Concepts and Precedents: LRAT and DRAT](CONCEPTS_AND_PRECEDENTS.md#lrat-and-drat) and inspect the executable certificate checker test in [`tests/test_gdc_certificate.py`](../tests/test_gdc_certificate.py).

### C. For Compiler and Systems Engineers
Compilers optimize programs across multiple intermediate representations (IR). A compiler bug can silently miscompile code into incorrect machine instructions:
- Translation validation proves that an IR transformation pass preserves program semantics.
- VSTD turns optimization passes into verifiable contracts: it binds input IR hash, output IR hash, translation validator tool, target CPU architecture, and OS environment constraints.
- Artifact control freezes intermediate artifacts into sealed, immutable bundles signed with cryptographic keys. If a thawed artifact or downstream dependency is modified by even a single byte, verification fails closed (`THAWED_DIRTY`).
- **Tutorial & Runnable Specimen**: Walk through [Seal an Artifact and Detect a Change](tutorials/SEAL_AN_ARTIFACT.md) and [Publish a Silo Package](tutorials/PUBLISH_A_SILO.md).

### D. For AI Safety Researchers and Transfinite Mathematicians
When analyzing self-referential systems, recursive agent loops, ordinal bounds, or non-well-founded belief graphs:
- Informal safety arguments frequently suffer from circular reasoning, ungrounded induction steps, or silent domain upgrades.
- VSTD enforces strict **stratified profiles (Profiles 1 to 5)**: a higher profile cannot supply or backfill missing evidence for a lower profile, and self-observation is never promoted to independent verification.
- Graph profiles track directed acyclic graphs (DAGs) and detect when an upstream dependency in an agent's reasoning chain has been revoked or invalidated.
- **Tutorial & Runnable Specimen**: Study the profile hierarchy in the [Normative Ladder](../standard/LADDER.md) and run the four adversarial specimens in [`examples/flagship_demo/`](../examples/flagship_demo/README.md).

### E. For Intellidynamics and AI Benchmarkers
Automated agent evaluations and language model leaderboards are plagued by prompt leaking, test-set contamination, and stochastic output variance:
- VSTD turns a benchmark score from an unproven assertion ("Model X scored 94%") into an auditable, refutable evidence bundle.
- It records exact prompt digests, model weights identifiers, temperature and random seed coordinates, frozen tool execution traces, and adversarial replay instructions.
- Anyone can re-run the exact verification recipe to confirm or falsify the benchmark score.
- **Tutorial & Runnable Specimen**: Walk through [Publishing a Benchmark Number Somebody Else Can Check](USE_CASES.md#1-publishing-a-benchmark-number-somebody-else-can-check) using [`examples/generic_run/manifest.json`](../examples/generic_run/manifest.json).

### F. For Deep Mathematics & Theorem Provers (Lean 4, Metamath, and Formal Kernels)
When working in advanced mathematical foundations, interactive theorem provers (such as Lean 4, Coq, Isabelle, or Metamath) and foundational algebraic kernels produce mechanically checked proofs:
- In formal mathematical ecosystems—such as `hypermath` (primitive foundational algebraic kernel, quadrilateral filtration, Lean 4 bridge), `ordinatics` (ordinal arithmetic, Veblen hierarchies, transfinite stage semantics), `grounded-hyperset-theory` (Aczel's Anti-Foundation Axiom (AFA), accessible pointed graphs (APGs), non-well-founded sets), and `grounded-hypercalculi` (Oracle, Language, Meta, Hyper, Ordinal, and Real Calculi, stratified reflection)—mathematical claims span multiple formal representations.
- A Lean 4 proof verifies a proposition relative to Lean's environment and axioms. But how do you verify cross-system mathematics—for example, connecting a Lean 4 theorem to a Python algebraic kernel, a SAT solver certificate, or a Metamath proof step without trusting a single monolithic system?
- VSTD provides the **meta-verification envelope**:
  1. **Axiom Enumeration**: It binds the exact explicit axiom set (refusing ungrounded axioms or `sorry` escapes).
  2. **Environment & Kernel Binding**: It hashes the exact prover kernel binary, source files, and dependencies.
  3. **Heterogeneous Composition**: It allows an ordinal bound in `ordinatics`, a hyperset graph in `grounded-hyperset-theory`, and an equational derivation in `hypermath` to link together into a unified, refutable proof graph.
- **Tutorial & Runnable Specimen**: Review [Python API Guide: Grounded Decision Certificates](PYTHON_API_GUIDE.md#grounded-decision-certificates-gdc) and the [Normative VSTD-4 Grounded Certificate Specification](../standard/VSTD-4.md).

### G. For Nanochemistry, Molecular Robotics & Mechanosynthesis (Self-Assembly Containment and Anti-Replication Gates)
In molecular dynamics simulations, chemical reaction networks (CRNs), and autonomous molecular robotics (such as deoxyribonucleic acid (DNA) origami walkers or mechanosynthetic tooltips), molecular self-assembly poses an urgent containment challenge: preventing runaway autocatalytic self-replication.

A molecular design tool or simulation might assert: *"This molecular machine only constructs the target crystal structure."* But in reality:
- Did the simulation explore parasitic reaction pathways where the machine synthesizes copies of its own catalytic core?
- What thermodynamic temperature ($T$), pressure ($P$), and solvent concentration bounds were verified?
- What happens if the design is sent to an automated robotic chemical synthesizer?

VSTD provides the computational containment seal:
1. **Coordinate and Stoichiometric Binding**: VSTD binds the exact atomic coordinate files, force-field potential parameter files, stoichiometric reaction matrices, and simulation integration steps into an immutable receipt.
2. **Refutation Route for Containment Claims**: An assertion of *"Non-self-replicating under standard physiological conditions"* is paired with an explicit refutation recipe: any researcher or adversary who demonstrates a reachable catalytic cycle (a series of reaction steps with activation energies below threshold $E_a < E_{\text{barrier}}$) leading to exponential autocatalysis overturns the claim.
3. **Synthesis Interlock**: Physical robotic nanofabrication devices can require an Ed25519-signed VSTD receipt proving that containment bounds were verified before releasing chemical feedstocks or beginning automated assembly.

- **Tutorial & Runnable Specimen**: Walk through [Seal an Artifact and Detect a Change](tutorials/SEAL_AN_ARTIFACT.md) and [Publishing a Benchmark Number Somebody Else Can Check](USE_CASES.md#1-publishing-a-benchmark-number-somebody-else-can-check).

---

## 5. Next steps

Now that you understand the mental model:
- [Run your first generic computation](FIRST_RECEIPT.md) — step-by-step tutorial capturing a word-frequency script into a receipt.
- [Explore the Python API](PYTHON_API_GUIDE.md) — generate and inspect receipts directly from your Python code.
- [Read the Normative Ladder](../standard/LADDER.md) — the formal specification of Profiles 1 through 5.
- [Inspect the Architecture Map](ARCHITECTURE.md) — internal module layout and design principles.
