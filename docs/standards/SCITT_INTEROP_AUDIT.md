# VSTD/SCITT integration sprint compliance audit

> **Status:** experimental, non-normative audit of the isolated SCITT branch.
> **Audit date:** 2026-08-23.
> **Immutable comparison base:** `598c545be3833d6d81bb7e252ca5837f3bb2a449`.
> This report does not imply IETF or SCITT Working Group review, interest,
> adoption, or endorsement.

## Audit method

The original 19-section sprint prompt was decomposed into **248 atomic
checklist items**. Files, symbols, source status, Git diff, generated artifacts,
real COSE execution, and tests were rechecked rather than inferred from file
presence. `PARTIAL` is not counted as complete.

## Defects found and fixed during this audit

1. The first adapter could compose an embedded receipt's declared `PASS` without a
   separately bound native VSTD checker observation. `compose_results` now requires
   `VstdVerificationEvidence` for the exact receipt digest.
2. The first demo replayed a grounded certificate without passing the reconstructed
   `ClaimBinding`. It now checks the exact claim, coordinate, roots, verifier
   descriptor, and bounds.
3. Deterministic Ed25519 private seeds were removed. Production uses fresh
   memory-only keys and emits only public trust coordinates.
4. Real cryptographic tests were added for resource exhaustion, a
   SCITT-valid/VSTD-rejected result, malformed COSE, and tampering.
5. SCITT statuses were refreshed, and overlapping individual drafts are no longer
   described as WG positions or ignored when discussing novelty.
6. The architecture was corrected: VSTD is the standard domain language and
   operator/result interlingua through which orchestrated domain verifiers, proof
   engines, signature/identity systems,
   transparency logs, provenance formats, and other verification substrata. It does
   not replace them.
7. The adjacent matrix now separates Reuse, Reference, Consume, and Do not replace.

## Requirement-by-requirement compliance matrix

| # | Original requirement | Status | Evidence | Gap / action |
|---:|---|---|---|---|
| 1 | Treat the original 19-section sprint prompt as the authoritative specification | COMPLETE | This matrix follows it section by section | None. |
| 2 | Determine exactly where VSTD and SCITT overlap | COMPLETE | `docs/standards/VSTD_SCITT_CROSSWALK.md` Result and Rigorous crosswalk | None. |
| 3 | Determine exactly where VSTD and SCITT differ | COMPLETE | Crosswalk Difference column and semantic-boundary document | None. |
| 4 | Implement the cleanest composition boundary without making VSTD compete with SCITT | COMPLETE | Optional bidirectional adapter with separate native results | None. |
| 5 | Read and obey AGENTS.md | COMPLETE | Repository identity, dependency, key-material, privacy, wire, and commit rules applied | None. |
| 6 | Read and obey standard/WIRE_IDENTIFIERS.md | COMPLETE | Normative and identifier diff is empty | None. |
| 7 | Inspect README.md. | COMPLETE | Read in this audit; findings reflected in crosswalk/boundary: `README.md`. | None. |
| 8 | Inspect standard/VSTD-1.md. | COMPLETE | Read in this audit; findings reflected in crosswalk/boundary: `standard/VSTD-1.md`. | None. |
| 9 | Inspect standard/VSTD-2.md. | COMPLETE | Read in this audit; findings reflected in crosswalk/boundary: `standard/VSTD-2.md`. | None. |
| 10 | Inspect standard/VSTD-3.md. | COMPLETE | Read in this audit; findings reflected in crosswalk/boundary: `standard/VSTD-3.md`. | None. |
| 11 | Inspect standard/VSTD-4.md. | COMPLETE | Read in this audit; findings reflected in crosswalk/boundary: `standard/VSTD-4.md`. | None. |
| 12 | Inspect standard/VSTD-5.md. | COMPLETE | Read in this audit; findings reflected in crosswalk/boundary: `standard/VSTD-5.md`. | None. |
| 13 | Inspect standard/VSTD-Graph-1.md. | COMPLETE | Read in this audit; findings reflected in crosswalk/boundary: `standard/VSTD-Graph-1.md`. | None. |
| 14 | Inspect standard/VSTD-Graph-2.md. | COMPLETE | Read in this audit; findings reflected in crosswalk/boundary: `standard/VSTD-Graph-2.md`. | None. |
| 15 | Inspect standard/VSTD-Graph-3.md. | COMPLETE | Read in this audit; findings reflected in crosswalk/boundary: `standard/VSTD-Graph-3.md`. | None. |
| 16 | Inspect standard/VSTD-Graph-4.md. | COMPLETE | Read in this audit; findings reflected in crosswalk/boundary: `standard/VSTD-Graph-4.md`. | None. |
| 17 | Inspect standard/VSTD-Graph-5.md. | COMPLETE | Read in this audit; findings reflected in crosswalk/boundary: `standard/VSTD-Graph-5.md`. | None. |
| 18 | Inspect standard/LADDER.md. | COMPLETE | Read in this audit; findings reflected in crosswalk/boundary: `standard/LADDER.md`. | None. |
| 19 | Inspect docs/CLAIMS_AND_LIMITS.md. | COMPLETE | Read in this audit; findings reflected in crosswalk/boundary: `docs/CLAIMS_AND_LIMITS.md`. | None. |
| 20 | Inspect docs/ECOSYSTEM.md. | COMPLETE | Read in this audit; findings reflected in crosswalk/boundary: `docs/ECOSYSTEM.md`. | None. |
| 21 | Inspect GOVERNANCE.md. | COMPLETE | Read in this audit; findings reflected in crosswalk/boundary: `GOVERNANCE.md`. | None. |
| 22 | Inspect ROADMAP.md. | COMPLETE | Read in this audit; findings reflected in crosswalk/boundary: `ROADMAP.md`. | None. |
| 23 | Inspect every receipt schema | COMPLETE | `receipts/schema/` inventory; VSTD-4 specimen schema validation test | None. |
| 24 | Inspect verifier/checker implementation | COMPLETE | `src/verifier/core/kernel.py`, core types, and SCITT adapter | None. |
| 25 | Inspect flagship examples | COMPLETE | Repository examples plus executed `examples/scitt_interop/` | None. |
| 26 | Inspect graph-validation tests | COMPLETE | Graph tests inventoried and included in full suite | None. |
| 27 | Inspect grounding and decision-certificate tests | COMPLETE | VSTD-4/kernel tests plus real demo certificate replay | None. |
| 28 | Inspect provenance behavior | COMPLETE | VSTD-3 provenance and VSTD-Graph implementation/tests | None. |
| 29 | Inspect revocation behavior | COMPLETE | Graph challenge/degradation and crosswalk lifecycle rows | None. |
| 30 | Identify current implementation instead of trusting prompt descriptions | COMPLETE | Boundary distinguishes implemented VSTD 1–4/Graph from draft VSTD-5/Graph-5 | None. |
| 31 | Do not modify normative semantics to ease SCITT integration | COMPLETE | Diff from base under `standard`, `receipts`, and core is empty | None. |
| 32 | Use current primary IETF sources | COMPLETE | Datatracker/RFC Editor rechecked on 2026-08-23 | None. |
| 33 | Inspect current primary material for RFC 9943 | COMPLETE | Proposed Standard; core architecture and accuracy boundary; exact status is in crosswalk source table | None. |
| 34 | Inspect current primary material for current SCITT architecture/API work | COMPLETE | SCRAPI -11, active WG draft in RFC Editor Queue; exact status is in crosswalk source table | None. |
| 35 | Inspect current primary material for COSE Receipt work | COMPLETE | RFC 9942 Proposed Standard and CCF profile -04; exact status is in crosswalk source table | None. |
| 36 | Inspect current primary material for Transparency Service semantics | COMPLETE | RFC 9943 sections 5–7; exact status is in crosswalk source table | None. |
| 37 | Inspect current primary material for registration policies | COMPLETE | RFC 9943 section 5.1.1; exact status is in crosswalk source table | None. |
| 38 | Inspect current primary material for statement-envelope semantics | COMPLETE | RFC 9943 Signed/Transparent Statements; exact status is in crosswalk source table | None. |
| 39 | Inspect current primary material for composite evidence verification | COMPLETE | composite-evidence -00; exact status is in crosswalk source table | None. |
| 40 | Inspect current primary material for SCITT statement graphs | COMPLETE | composite-evidence and protected-object-binding -00; exact status is in crosswalk source table | None. |
| 41 | Inspect current primary material for AI transparency receipts | COMPLETE | Article 50 -00 and AI Agent Receipt -01; exact status is in crosswalk source table | None. |
| 42 | Inspect current primary material for execution evidence | COMPLETE | agent-execution -00; exact status is in crosswalk source table | None. |
| 43 | Inspect current primary material for agent/action receipts | COMPLETE | AI Agent Receipt -01 and Action Capsule -02; exact status is in crosswalk source table | None. |
| 44 | Inspect current primary material for evidence bundles | COMPLETE | composite-evidence -00 sections 10–12; exact status is in crosswalk source table | None. |
| 45 | Inspect current primary material for revocation | COMPLETE | RFC 9943 key-compromise limits and composite proposal; exact status is in crosswalk source table | None. |
| 46 | Inspect current primary material for supersession | COMPLETE | RFC 9943 section 9.2 and composite proposal; exact status is in crosswalk source table | None. |
| 47 | Inspect current primary material for verification profiles | COMPLETE | RFC 9942 profiles and composite proposal; exact status is in crosswalk source table | None. |
| 48 | Classify Proposed Standard RFCs separately | COMPLETE | RFC 9942 and RFC 9943 labeled Proposed Standard | None. |
| 49 | Classify adopted Working Group drafts separately | COMPLETE | SCRAPI -11 and CCF profile -04 labeled active SCITT WG drafts | None. |
| 50 | Classify individual Internet-Drafts separately | COMPLETE | Each listed individual proposal is explicitly labeled no WG adoption/formal standing | None. |
| 51 | Classify expired drafts separately | COMPLETE | No expired draft relied upon; replaced/older revisions excluded | None. |
| 52 | Never blur RFC, WG draft, individual draft, and expired status | COMPLETE | Crosswalk status table and engagement pre-send checklist | None. |
| 53 | Test VSTD inside SCITT | COMPLETE | Complete receipt carried by real COSE Signed Statement | None. |
| 54 | Test SCITT evidence inside VSTD | COMPLETE | `consume_scitt_evidence` returns `SCITT_TRANSPARENCY/NOT_EVALUATED` | None. |
| 55 | Test bidirectional composition | COMPLETE | Both directions implemented and executed | None. |
| 56 | Test graph composition | COMPLETE | Crosswalk Architecture decision item 3; experimental only | None. |
| 57 | Determine the cleanest arrangement | COMPLETE | Optional bidirectional composition with separate native verdicts | None. |
| 58 | Confirm or falsify the provisional thesis | COMPLETE | Corrected: VSTD is the verification interlingua and operator/result language over orchestrated native engines, not a domain-engine replacement | None. |
| 59 | Create docs/standards/VSTD_SCITT_CROSSWALK.md | COMPLETE | Named substantive deliverable | None. |
| 60 | Use Concern, VSTD, SCITT, Overlap, Difference, and Composition columns | COMPLETE | Six-column rigorous crosswalk | None. |
| 61 | Crosswalk claim identity. | COMPLETE | Named crosswalk row: `claim identity`. | None. |
| 62 | Crosswalk subject identity. | COMPLETE | Named crosswalk row: `subject identity`. | None. |
| 63 | Crosswalk predicates. | COMPLETE | Named crosswalk row: `predicates`. | None. |
| 64 | Crosswalk parameters. | COMPLETE | Named crosswalk row: `parameters`. | None. |
| 65 | Crosswalk explicit limits. | COMPLETE | Named crosswalk row: `explicit limits`. | None. |
| 66 | Crosswalk issuer identity. | COMPLETE | Named crosswalk row: `issuer identity`. | None. |
| 67 | Crosswalk signatures. | COMPLETE | Named crosswalk row: `signatures`. | None. |
| 68 | Crosswalk artifact binding. | COMPLETE | Named crosswalk row: `artifact binding`. | None. |
| 69 | Crosswalk statement registration. | COMPLETE | Named crosswalk row: `statement registration`. | None. |
| 70 | Crosswalk transparency. | COMPLETE | Named crosswalk row: `transparency`. | None. |
| 71 | Crosswalk append-only logs. | COMPLETE | Named crosswalk row: `append-only logs`. | None. |
| 72 | Crosswalk portable receipts. | COMPLETE | Named crosswalk row: `portable receipts`. | None. |
| 73 | Crosswalk evidence bundles. | COMPLETE | Named crosswalk row: `evidence bundles`. | None. |
| 74 | Crosswalk provenance graphs. | COMPLETE | Named crosswalk row: `provenance graphs`. | None. |
| 75 | Crosswalk statement graphs. | COMPLETE | Named crosswalk row: `statement graphs`. | None. |
| 76 | Crosswalk dependencies. | COMPLETE | Named crosswalk row: `dependencies`. | None. |
| 77 | Crosswalk revocation. | COMPLETE | Named crosswalk row: `revocation`. | None. |
| 78 | Crosswalk supersession. | COMPLETE | Named crosswalk row: `supersession`. | None. |
| 79 | Crosswalk conflicts. | COMPLETE | Named crosswalk row: `conflicts`. | None. |
| 80 | Crosswalk freshness. | COMPLETE | Named crosswalk row: `freshness`. | None. |
| 81 | Crosswalk verification profiles. | COMPLETE | Named crosswalk row: `verification profiles`. | None. |
| 82 | Crosswalk resource bounds. | COMPLETE | Named crosswalk row: `resource bounds`. | None. |
| 83 | Crosswalk computational grounding. | COMPLETE | Named crosswalk row: `computational grounding`. | None. |
| 84 | Crosswalk reproduction. | COMPLETE | Named crosswalk row: `reproduction`. | None. |
| 85 | Crosswalk independent checking. | COMPLETE | Named crosswalk row: `independent checking`. | None. |
| 86 | Crosswalk counterexamples. | COMPLETE | Named crosswalk row: `counterexamples`. | None. |
| 87 | Crosswalk PASS. | COMPLETE | Named crosswalk row: `PASS`. | None. |
| 88 | Crosswalk FAIL. | COMPLETE | Named crosswalk row: `FAIL`. | None. |
| 89 | Crosswalk UNKNOWN. | COMPLETE | Named crosswalk row: `UNKNOWN`. | None. |
| 90 | Crosswalk warnings. | COMPLETE | Named crosswalk row: `warnings`. | None. |
| 91 | Crosswalk cost/work claims. | COMPLETE | Named crosswalk row: `cost/work claims`. | None. |
| 92 | Crosswalk graph degradation. | COMPLETE | Named crosswalk row: `graph degradation`. | None. |
| 93 | Crosswalk real-world truth versus evidence validity. | COMPLETE | Named crosswalk row: `real-world truth versus evidence validity`. | None. |
| 94 | Identify what SCITT already does well without relabeling it as VSTD | COMPLETE | Crosswalk section What SCITT already does well | None. |
| 95 | Claim only VSTD differentiation supported by normative text and implementation | COMPLETE | Crosswalk section Current overlap and narrower VSTD contribution | None. |
| 96 | Distinguish UNKNOWN-related condition: unavailable evidence. | COMPLETE | Crosswalk UNKNOWN taxonomy: `unavailable evidence`. | None. |
| 97 | Distinguish UNKNOWN-related condition: incomplete evidence. | COMPLETE | Crosswalk UNKNOWN taxonomy: `incomplete evidence`. | None. |
| 98 | Distinguish UNKNOWN-related condition: stale evidence. | COMPLETE | Crosswalk UNKNOWN taxonomy: `stale evidence`. | None. |
| 99 | Distinguish UNKNOWN-related condition: conflicting evidence. | COMPLETE | Crosswalk UNKNOWN taxonomy: `conflicting evidence`. | None. |
| 100 | Distinguish UNKNOWN-related condition: revoked evidence. | COMPLETE | Crosswalk UNKNOWN taxonomy: `revoked evidence`. | None. |
| 101 | Distinguish UNKNOWN-related condition: unsupported verification method. | COMPLETE | Crosswalk UNKNOWN taxonomy: `unsupported verification method`. | None. |
| 102 | Distinguish UNKNOWN-related condition: verifier resource-budget exhaustion. | COMPLETE | Crosswalk UNKNOWN taxonomy: `verifier resource-budget exhaustion`. | None. |
| 103 | Distinguish UNKNOWN-related condition: bounded inability to establish the predicate. | COMPLETE | Crosswalk UNKNOWN taxonomy: `bounded inability to establish the predicate`. | None. |
| 104 | Distinguish UNKNOWN-related condition: explicit failure. | COMPLETE | Crosswalk UNKNOWN taxonomy: `explicit failure`. | None. |
| 105 | Determine whether SCITT and VSTD UNKNOWN are semantically equivalent | COMPLETE | Explicit answer: no; SCITT core has no generic application verdict and individual-draft labels are profile-specific | None. |
| 106 | Identify the exact VSTD-shaped hole | COMPLETE | Operator/result-semantics boundary in crosswalk Result and Positioning | None. |
| 107 | Do not settle for an unsupported slogan | COMPLETE | Novelty language corrected after overlap research | None. |
| 108 | Implement a small isolated interoperability module | COMPLETE | `src/verifier/interoperability/scitt/adapter.py` | None. |
| 109 | Use repository-consistent location | COMPLETE | Existing `src/verifier/interoperability/` package | None. |
| 110 | Do not implement an entire Transparency Service | COMPLETE | Local one-entry cryptographic specimen only; explicit non-production limit | None. |
| 111 | Implement VSTD receipt/result to SCITT-compatible statement mapping | COMPLETE | `VstdCoordinates`, `VstdScittPayload`, registration template | None. |
| 112 | Implement SCITT receipt/statement to VSTD evidence mapping where supported | COMPLETE | `ScittVerificationEvidence` and `consume_scitt_evidence` | None. |
| 113 | Provide deterministic serialization where required | COMPLETE | `canonical_json_bytes` and deterministic payload test | None. |
| 114 | Provide explicit version identifiers | COMPLETE | mapping version, profile, content type; rejection tests | None. |
| 115 | Preserve VSTD claim coordinates | COMPLETE | closed coordinate projection and round-trip/mismatch tests | None. |
| 116 | Preserve artifact identities | COMPLETE | artifact digest mapping and substitution test | None. |
| 117 | Preserve bounds | COMPLETE | evidence bounds mapping and real budget test | None. |
| 118 | Preserve UNKNOWN | COMPLETE | indeterminate state and composition tests | None. |
| 119 | Preserve provenance references | COMPLETE | round-trip assertion | None. |
| 120 | Reject unsupported mappings rather than guessing | COMPLETE | closed shapes and version/profile/native-result rejections | None. |
| 121 | Prevent semantic upgrading | COMPLETE | composition requires exact digest-bound native VSTD observation plus verified SCITT evidence | None. |
| 122 | Create a self-contained end-to-end example | COMPLETE | `examples/scitt_interop/` includes artifact, demo, docs, public trust artifacts, and tests | None. |
| 123 | Make the complete cryptographic example byte-for-byte deterministic | PARTIAL | VSTD receipt/application payload is deterministic; newly produced COSE bytes use fresh memory-only Ed25519 keys | Full byte determinism conflicts with the repository rule forbidding committed test private-key material. Disclose limited determinism; do not weaken key hygiene. |
| 124 | Demonstrate pipeline step: real computational claim. | COMPLETE | Executed `examples/scitt_interop/demo.py` produce/verify path: `real computational claim`. | None. |
| 125 | Demonstrate pipeline step: VSTD evidence. | COMPLETE | Executed `examples/scitt_interop/demo.py` produce/verify path: `VSTD evidence`. | None. |
| 126 | Demonstrate pipeline step: VSTD verification. | COMPLETE | Executed `examples/scitt_interop/demo.py` produce/verify path: `VSTD verification`. | None. |
| 127 | Demonstrate pipeline step: VSTD result/receipt. | COMPLETE | Executed `examples/scitt_interop/demo.py` produce/verify path: `VSTD result/receipt`. | None. |
| 128 | Demonstrate pipeline step: SCITT-compatible statement. | COMPLETE | Executed `examples/scitt_interop/demo.py` produce/verify path: `SCITT-compatible statement`. | None. |
| 129 | Demonstrate pipeline step: transparency/receipt representation. | COMPLETE | Executed `examples/scitt_interop/demo.py` produce/verify path: `transparency/receipt representation`. | None. |
| 130 | Demonstrate pipeline step: independent consumption. | COMPLETE | Executed `examples/scitt_interop/demo.py` produce/verify path: `independent consumption`. | None. |
| 131 | Implement reverse-direction consumption if practical | COMPLETE | Demo emits REGISTERED SCITT transparency evidence with `computational_verdict=NOT_EVALUATED` | None. |
| 132 | Execute artifact substitution | COMPLETE | SCITT REGISTERED; original VSTD PASS; composition FAIL | None. |
| 133 | Execute valid SCITT registration with an invalid underlying computational claim | COMPLETE | real signature/receipt verified; VSTD REJECTED; composition FAIL | None. |
| 134 | Execute missing required evidence | COMPLETE | SCITT MISSING; VSTD PASS; composition UNKNOWN | None. |
| 135 | Execute revoked evidence | COMPLETE | SCITT REVOKED; historical state retained; composition UNKNOWN | None. |
| 136 | Execute superseded evidence | COMPLETE | SCITT SUPERSEDED; historical state retained; composition UNKNOWN | None. |
| 137 | Execute resource exhaustion | COMPLETE | real signature/receipt verified; VSTD REFUSED/UNKNOWN; composition UNKNOWN | None. |
| 138 | Test serialization | COMPLETE | `tests/test_scitt_interop.py` / `tests/test_scitt_crypto_example.py`: deterministic payload test | None. |
| 139 | Test round-trip identity | COMPLETE | `tests/test_scitt_interop.py` / `tests/test_scitt_crypto_example.py`: payload and evidence round-trip tests | None. |
| 140 | Test claim-coordinate preservation | COMPLETE | `tests/test_scitt_interop.py` / `tests/test_scitt_crypto_example.py`: coordinate mismatch rejection | None. |
| 141 | Test hash and artifact binding | COMPLETE | `tests/test_scitt_interop.py` / `tests/test_scitt_crypto_example.py`: substitution and payload-transplant tests | None. |
| 142 | Test unsupported mappings | COMPLETE | `tests/test_scitt_interop.py` / `tests/test_scitt_crypto_example.py`: unsupported result/profile/version tests | None. |
| 143 | Test SCITT-valid but VSTD-invalid inputs | COMPLETE | `tests/test_scitt_interop.py` / `tests/test_scitt_crypto_example.py`: unit and real-COSE rejected-claim tests | None. |
| 144 | Test VSTD-valid but SCITT-missing inputs | COMPLETE | `tests/test_scitt_interop.py` / `tests/test_scitt_crypto_example.py`: MISSING state test | None. |
| 145 | Test UNKNOWN preservation | COMPLETE | `tests/test_scitt_interop.py` / `tests/test_scitt_crypto_example.py`: native VSTD and SCITT noncurrent-state tests | None. |
| 146 | Test tampering | COMPLETE | `tests/test_scitt_interop.py` / `tests/test_scitt_crypto_example.py`: real statement and receipt tamper test | None. |
| 147 | Test revoked evidence | COMPLETE | `tests/test_scitt_interop.py` / `tests/test_scitt_crypto_example.py`: REVOKED state test | None. |
| 148 | Test malformed statements | COMPLETE | `tests/test_scitt_interop.py` / `tests/test_scitt_crypto_example.py`: real malformed COSE statement test | None. |
| 149 | Test version mismatches | COMPLETE | `tests/test_scitt_interop.py` / `tests/test_scitt_crypto_example.py`: mapping/profile version test | None. |
| 150 | Test bounded resource exhaustion | COMPLETE | `tests/test_scitt_interop.py` / `tests/test_scitt_crypto_example.py`: real budget-zero test | None. |
| 151 | Enforce that SCITT REGISTERED cannot create VSTD PASS without native VSTD verification | COMPLETE | exact no-upgrade, digest-binding, rejected-claim, and budget-exhaustion tests | None. |
| 152 | Run the relevant full repository test suite | COMPLETE | Final validation: 279 passed, 4 skipped | None. |
| 153 | Run the new SCITT interoperability tests | COMPLETE | Final validation: 36 passed | None. |
| 154 | Create docs/standards/SCITT_SEMANTIC_BOUNDARY.md | COMPLETE | Named substantive deliverable | None. |
| 155 | Explain only what current SCITT can establish | COMPLETE | Trust-coordinate-qualified SCITT section and RFC accuracy boundary | None. |
| 156 | Explain only what current VSTD can establish | COMPLETE | Operator-layer section distinguishes implemented and draft layers | None. |
| 157 | State that neither layer automatically establishes arbitrary real-world truth. | COMPLETE | Semantic-boundary Neither establishes automatically section: `arbitrary real-world truth`. | None. |
| 158 | State that neither layer automatically establishes causal correctness. | COMPLETE | Semantic-boundary Neither establishes automatically section: `causal correctness`. | None. |
| 159 | State that neither layer automatically establishes safety. | COMPLETE | Semantic-boundary Neither establishes automatically section: `safety`. | None. |
| 160 | State that neither layer automatically establishes completeness of undisclosed evidence. | COMPLETE | Semantic-boundary Neither establishes automatically section: `completeness of undisclosed evidence`. | None. |
| 161 | State that neither layer automatically establishes rights or authorization from provenance. | COMPLETE | Semantic-boundary Neither establishes automatically section: `rights or authorization from provenance`. | None. |
| 162 | State that neither layer automatically establishes provenance from integrity. | COMPLETE | Semantic-boundary Neither establishes automatically section: `provenance from integrity`. | None. |
| 163 | State that neither layer automatically establishes correctness from signature validity. | COMPLETE | Semantic-boundary Neither establishes automatically section: `correctness from signature validity`. | None. |
| 164 | Make the semantic-boundary document suitable for standards engineers | COMPLETE | Precise propositions, trust coordinates, status language, and non-endorsement disclaimer | None. |
| 165 | Create docs/standards/IETF_SCITT_ENGAGEMENT.md | COMPLETE | Named substantive deliverable | None. |
| 166 | Include a concise, non-hype VSTD introduction | COMPLETE | One-paragraph introduction | None. |
| 167 | Explain the technical VSTD/SCITT relationship | COMPLETE | Operator over orchestrated substrates in Technical relationship | None. |
| 168 | Include at least three substantive questions | COMPLETE | Three questions on payload boundary, composite result semantics, and historical/current state | None. |
| 169 | Suggest a concrete contribution | COMPLETE | Crosswalk, specimen, implementation, and negative tests offered first | None. |
| 170 | Do not assume which contribution the WG wants | COMPLETE | Contribution forms are posed as questions | None. |
| 171 | Do not send any external message without human review | COMPLETE | Prominent do-not-send rule; no external contact performed | None. |
| 172 | Consider Internet-Draft maturity option A — no draft yet | COMPLETE | Engagement maturity section | None. |
| 173 | Consider Internet-Draft maturity option B — informational interoperability/profile draft | COMPLETE | Engagement maturity section | None. |
| 174 | Consider Internet-Draft maturity option C — VSTD evidence statement type | COMPLETE | Engagement maturity section | None. |
| 175 | Consider Internet-Draft maturity option D — bounded computational-verification profile | COMPLETE | Engagement maturity section | None. |
| 176 | Consider Internet-Draft maturity option E — implementation report first | COMPLETE | Engagement maturity section | None. |
| 177 | Recommend the correct maturity level | COMPLETE | Option E now; reconsider Option B only after community and interoperability evidence | None. |
| 178 | Create a concise adjacent-standards matrix | COMPLETE | `docs/standards/ADJACENT_STANDARDS_MATRIX.md` | None. |
| 179 | For IETF SCITT, state what VSTD should reuse | COMPLETE | Separate Reuse, Reference, Consume, and Do not replace matrix columns | None. |
| 180 | For IETF SCITT, state what VSTD should reference | COMPLETE | Separate Reuse, Reference, Consume, and Do not replace matrix columns | None. |
| 181 | For IETF SCITT, state what VSTD can consume | COMPLETE | Separate Reuse, Reference, Consume, and Do not replace matrix columns | None. |
| 182 | For IETF SCITT, state what VSTD should not replace | COMPLETE | Separate Reuse, Reference, Consume, and Do not replace matrix columns | None. |
| 183 | For in-toto, state what VSTD should reuse | COMPLETE | Separate Reuse, Reference, Consume, and Do not replace matrix columns | None. |
| 184 | For in-toto, state what VSTD should reference | COMPLETE | Separate Reuse, Reference, Consume, and Do not replace matrix columns | None. |
| 185 | For in-toto, state what VSTD can consume | COMPLETE | Separate Reuse, Reference, Consume, and Do not replace matrix columns | None. |
| 186 | For in-toto, state what VSTD should not replace | COMPLETE | Separate Reuse, Reference, Consume, and Do not replace matrix columns | None. |
| 187 | For SLSA, state what VSTD should reuse | COMPLETE | Separate Reuse, Reference, Consume, and Do not replace matrix columns | None. |
| 188 | For SLSA, state what VSTD should reference | COMPLETE | Separate Reuse, Reference, Consume, and Do not replace matrix columns | None. |
| 189 | For SLSA, state what VSTD can consume | COMPLETE | Separate Reuse, Reference, Consume, and Do not replace matrix columns | None. |
| 190 | For SLSA, state what VSTD should not replace | COMPLETE | Separate Reuse, Reference, Consume, and Do not replace matrix columns | None. |
| 191 | For Sigstore, state what VSTD should reuse | COMPLETE | Separate Reuse, Reference, Consume, and Do not replace matrix columns | None. |
| 192 | For Sigstore, state what VSTD should reference | COMPLETE | Separate Reuse, Reference, Consume, and Do not replace matrix columns | None. |
| 193 | For Sigstore, state what VSTD can consume | COMPLETE | Separate Reuse, Reference, Consume, and Do not replace matrix columns | None. |
| 194 | For Sigstore, state what VSTD should not replace | COMPLETE | Separate Reuse, Reference, Consume, and Do not replace matrix columns | None. |
| 195 | For C2PA, state what VSTD should reuse | COMPLETE | Separate Reuse, Reference, Consume, and Do not replace matrix columns | None. |
| 196 | For C2PA, state what VSTD should reference | COMPLETE | Separate Reuse, Reference, Consume, and Do not replace matrix columns | None. |
| 197 | For C2PA, state what VSTD can consume | COMPLETE | Separate Reuse, Reference, Consume, and Do not replace matrix columns | None. |
| 198 | For C2PA, state what VSTD should not replace | COMPLETE | Separate Reuse, Reference, Consume, and Do not replace matrix columns | None. |
| 199 | For W3C PROV, state what VSTD should reuse | COMPLETE | Separate Reuse, Reference, Consume, and Do not replace matrix columns | None. |
| 200 | For W3C PROV, state what VSTD should reference | COMPLETE | Separate Reuse, Reference, Consume, and Do not replace matrix columns | None. |
| 201 | For W3C PROV, state what VSTD can consume | COMPLETE | Separate Reuse, Reference, Consume, and Do not replace matrix columns | None. |
| 202 | For W3C PROV, state what VSTD should not replace | COMPLETE | Separate Reuse, Reference, Consume, and Do not replace matrix columns | None. |
| 203 | For SPDX, state what VSTD should reuse | COMPLETE | Separate Reuse, Reference, Consume, and Do not replace matrix columns | None. |
| 204 | For SPDX, state what VSTD should reference | COMPLETE | Separate Reuse, Reference, Consume, and Do not replace matrix columns | None. |
| 205 | For SPDX, state what VSTD can consume | COMPLETE | Separate Reuse, Reference, Consume, and Do not replace matrix columns | None. |
| 206 | For SPDX, state what VSTD should not replace | COMPLETE | Separate Reuse, Reference, Consume, and Do not replace matrix columns | None. |
| 207 | For relevant attestation formats (RATS, EAT, CoRIM, DSSE), state what VSTD should reuse | COMPLETE | Separate Reuse, Reference, Consume, and Do not replace matrix columns | None. |
| 208 | For relevant attestation formats (RATS, EAT, CoRIM, DSSE), state what VSTD should reference | COMPLETE | Separate Reuse, Reference, Consume, and Do not replace matrix columns | None. |
| 209 | For relevant attestation formats (RATS, EAT, CoRIM, DSSE), state what VSTD can consume | COMPLETE | Separate Reuse, Reference, Consume, and Do not replace matrix columns | None. |
| 210 | For relevant attestation formats (RATS, EAT, CoRIM, DSSE), state what VSTD should not replace | COMPLETE | Separate Reuse, Reference, Consume, and Do not replace matrix columns | None. |
| 211 | Use adjacent-standard analysis to prevent reinvention | COMPLETE | Design rule and Do not replace column | None. |
| 212 | Keep SCITT as the sprint's primary target | COMPLETE | Matrix status note and bounded scope | None. |
| 213 | Treat existing-standard composition as a design advantage | COMPLETE | Crosswalk and adjacent matrix shrink VSTD around native systems | None. |
| 214 | Prefer VSTD plus an existing standard when semantics are preserved | COMPLETE | Adapter preserves native bytes, identifiers, trust roots, and results | None. |
| 215 | Keep experimental SCITT work separate from normative VSTD | COMPLETE | All artifacts labeled experimental/non-normative and isolated in docs/examples/interoperability/tests | None. |
| 216 | Do not modify core VSTD semantics | COMPLETE | Normative diff empty | None. |
| 217 | Do not renumber wire identifiers | COMPLETE | Wire identifier files unchanged | None. |
| 218 | Do not change normative receipt structures | COMPLETE | Schemas unchanged; full receipt wrapped | None. |
| 219 | Do not make existing receipts incompatible | COMPLETE | Core/schema behavior unchanged; full suite passes | None. |
| 220 | Document a proposed normative change separately if necessary | NOT APPLICABLE — JUSTIFIED | No normative change proved necessary | Revisit only if review exposes a normative defect. |
| 221 | Do not say IETF supports VSTD | COMPLETE | Non-endorsement statements | None. |
| 222 | Do not say SCITT validates VSTD | COMPLETE | Two-receipts/two-propositions rule and `NOT_EVALUATED` | None. |
| 223 | Do not say VSTD is becoming an IETF standard | COMPLETE | Implementation-report-first recommendation | None. |
| 224 | Use precise experimental interoperability language | COMPLETE | Experimental/non-normative and conditional mapping wording | None. |
| 225 | Deliver docs/standards/VSTD_SCITT_CROSSWALK.md. | COMPLETE | Present and inspected: `docs/standards/VSTD_SCITT_CROSSWALK.md`. | None. |
| 226 | Deliver docs/standards/SCITT_SEMANTIC_BOUNDARY.md. | COMPLETE | Present and inspected: `docs/standards/SCITT_SEMANTIC_BOUNDARY.md`. | None. |
| 227 | Deliver docs/standards/IETF_SCITT_ENGAGEMENT.md. | COMPLETE | Present and inspected: `docs/standards/IETF_SCITT_ENGAGEMENT.md`. | None. |
| 228 | Deliver docs/standards/ADJACENT_STANDARDS_MATRIX.md. | COMPLETE | Present and inspected: `docs/standards/ADJACENT_STANDARDS_MATRIX.md`. | None. |
| 229 | Deliver examples/scitt_interop/. | COMPLETE | Present and inspected: `examples/scitt_interop/`. | None. |
| 230 | Deliver src/verifier/interoperability/scitt/. | COMPLETE | Present and inspected: `src/verifier/interoperability/scitt/`. | None. |
| 231 | Deliver tests/test_scitt_interop.py. | COMPLETE | Present and inspected: `tests/test_scitt_interop.py`. | None. |
| 232 | Deliver tests/test_scitt_crypto_example.py. | COMPLETE | Present and inspected: `tests/test_scitt_crypto_example.py`. | None. |
| 233 | Follow actual repository naming and layout conventions | COMPLETE | Source under `src/verifier`; examples/docs/tests use existing layout | None. |
| 234 | Answer final-report question 1: How close is SCITT to VSTD? | COMPLETE | Explicit numbered answer 1 below | None. |
| 235 | Answer final-report question 2: What does SCITT already solve that VSTD should stop trying to solve itself? | COMPLETE | Explicit numbered answer 2 below | None. |
| 236 | Answer final-report question 3: What important capability remains distinctively VSTD? | COMPLETE | Explicit numbered answer 3 below | None. |
| 237 | Answer final-report question 4: What is the cleanest VSTD-SCITT architecture? | COMPLETE | Explicit numbered answer 4 below | None. |
| 238 | Answer final-report question 5: Can VSTD receipts be carried as SCITT statements without semantic loss? | COMPLETE | Explicit numbered answer 5 below | None. |
| 239 | Answer final-report question 6: Can SCITT receipts serve as VSTD evidence, and under what policy? | COMPLETE | Explicit numbered answer 6 below | None. |
| 240 | Answer final-report question 7: What does VSTD add to composite-evidence verification? | COMPLETE | Explicit numbered answer 7 below | None. |
| 241 | Answer final-report question 8: Which current SCITT document is closest to VSTD, with exact status? | COMPLETE | Explicit numbered answer 8 below | None. |
| 242 | Answer final-report question 9: What interoperability work was implemented? | COMPLETE | Explicit numbered answer 9 below | None. |
| 243 | Answer final-report question 10: Which tests demonstrate no SCITT-integrity-to-VSTD-truth laundering? | COMPLETE | Explicit numbered answer 10 below | None. |
| 244 | Answer final-report question 11: Should the SCITT mailing list be engaged now, and how? | COMPLETE | Explicit numbered answer 11 below | None. |
| 245 | Answer final-report question 12: Should an Internet-Draft be prepared now, later, or not at all? | COMPLETE | Explicit numbered answer 12 below | None. |
| 246 | Answer final-report question 13: What is the strongest positioning sentence? | COMPLETE | Explicit numbered answer 13 below | None. |
| 247 | Answer final-report question 14: What is the strongest technical demo? | COMPLETE | Explicit numbered answer 14 below | None. |
| 248 | Answer final-report question 15: What is unfinished before engagement? | COMPLETE | Explicit numbered answer 15 below | None. |


## Original final-report questions — explicit answers

1. **How close is SCITT to VSTD?** A percentage would be misleading because the
   layers answer partly orthogonal questions. SCITT is standardized for signed
   statement authenticity, registration policy, transparency/VDS properties, and
   portable COSE receipts. VSTD is the domain language for portable claim boundaries
   and results across native verification substrata. Active individual SCITT drafts
   overlap some result and graph vocabulary but are not WG standards.
2. **What does SCITT already solve that VSTD should stop trying to solve itself?**
   COSE envelopes, issuer/subject authentication, registration policy, Transparency
   Service APIs, append-only/non-equivocating VDS behavior, COSE Receipt
   attachment/verification, and TS-key discovery.
3. **What remains distinctively VSTD?** In this repository, a domain-general
   verification interlingua that preserves a native engine's exact claim, evidence,
   policy, verifier, budget, result, UNKNOWN, refutation, and degradation boundary.
   This is an implementation distinction, not a universal novelty claim.
4. **What is the cleanest architecture?** Optional bidirectional composition with
   separate native results: carry a complete VSTD receipt as a SCITT application
   payload when transparency is wanted; consume verified SCITT registration as typed
   transparency evidence; never upgrade either native result.
5. **Can VSTD receipts be carried as SCITT statements without semantic loss?** Yes
   for the implemented full-receipt mapping, provided the receipt, coordinates,
   bounds, artifact digests, provenance references, mapping version, payload digest,
   and native checker result all remain visible. Selective projection needs its own
   loss analysis.
6. **Can SCITT receipts serve as VSTD evidence? Under what policy?** Yes, narrowly,
   after native statement and COSE Receipt verification under named issuer, subject,
   payload digest, TS, VDS/profile, registration policy, key, time/freshness, and
   lifecycle assumptions. The adapted result is `SCITT_TRANSPARENCY/NOT_EVALUATED`,
   not computational PASS.
7. **What does VSTD add to composite-evidence verification?** A concrete portable
   contract binding a native verifier's receipt/result to claim coordinates,
   artifacts, roots, resource ceiling, and refutation surface. The individual
   composite draft already proposes graphs, bundles, profiles, missing, stale,
   conflict, warning, and unknown outcomes; VSTD does not claim those as unique.
8. **Which current SCITT document is closest?**
   `draft-nobuo-scitt-composite-evidence-verification-00`, an **active individual
   Internet-Draft with no WG adoption or formal standing**. AI Agent Receipt -01 is
   also close on narrow-claim and validity/sufficiency boundaries and has the same
   individual-draft status.
9. **What was implemented?** A strict adapter; canonical application payload;
   normalized native VSTD and SCITT evidence; monotone composition; real EdDSA COSE
   Signed Statement; real RFC9162-SHA256 inclusion receipt; reverse evidence adapter;
   end-to-end example; documentation; and 36 focused tests.
10. **Which tests prove no integrity-to-truth laundering?**
    `test_registered_scitt_cannot_create_pass_without_bound_vstd_verification`,
    `test_vstd_checker_result_must_bind_exact_receipt_and_native_result`,
    `test_rejected_vstd_receipt_cannot_be_repaired_by_scitt_registration`,
    `test_real_scitt_registration_does_not_upgrade_vstd_budget_exhaustion`, and
    `test_real_valid_scitt_registration_does_not_repair_rejected_vstd_claim`.
11. **Should the SCITT mailing list be engaged now?** Yes for initial technical
    correction, not adoption. After human review and publication, send one compact
    implementation-report message that states the RFC 9943 accuracy boundary, links
    code/crosswalk/tests, discloses the local log and lack of an independent
    implementation, and asks the three bounded questions in the engagement package.
12. **Should an Internet-Draft be prepared?** Later if discussion supports it.
    Choose Option E now (implementation report first); reconsider Option B
    (informational payload profile) after feedback and independent/native
    interoperability. Options C and D are premature.
13. **Strongest positioning sentence:** “SCITT can authenticate and make a VSTD
    receipt's registration transparently auditable; VSTD supplies the verification
    interlingua that preserves the bounded claim boundary and portable result
    semantics of the native verifier or proof engine that produced the result.”
14. **Strongest technical demo:** With real signatures and receipts, show an exact
    VSTD claim composing to PASS, a binding-invalid VSTD witness composing to FAIL
    while SCITT remains REGISTERED, and a budget-zero check composing to UNKNOWN
    while SCITT remains REGISTERED.
15. **What remains before engagement?** No substantive blocker for an initial
    technical inquiry. Disclose that the TS is a local one-entry log, there is no
    external implementation, identifiers are experimental, and fresh memory-only
    keys intentionally prevent byte-identical COSE regeneration.

## Executed end-to-end path

```powershell
python examples/scitt_interop/demo.py produce --output <TEMP>
python examples/scitt_interop/demo.py verify --output <TEMP>
```

Observed: native VSTD `ACCEPTED/PASS`; Signed Statement signature verified; COSE
Receipt verified; SCITT state `REGISTERED`; composition `PASS`; reverse adapter
`REGISTERED/NOT_EVALUATED`. Stable artifact digest:
`39c442988b425a1e4cc7c6bb41d4fb35046dea61a5be3cdf39a582b054eae341`.
Deterministic application-payload digest:
`38a21c5d1a5aa9feb99626d7631a626d5b140f39486117a9954afb54ae2fb661`.

## Executed adversarial outcomes

| Case | SCITT layer | VSTD layer | Composition | Reason |
|---|---|---|---|---|
| Artifact substitution | REGISTERED | PASS for original artifact | FAIL | Observed artifact digest differs from bound digest. |
| Valid registration, invalid claim | REGISTERED; signature/receipt verified | REJECTED | FAIL | Registration does not establish the computational claim. |
| Missing required evidence | MISSING | PASS | UNKNOWN | Optional transparency proposition is unestablished. |
| Revoked evidence | REVOKED | PASS | UNKNOWN | Historical inclusion remains; current admissibility does not. |
| Superseded evidence | SUPERSEDED | PASS | UNKNOWN | Newer does not mean truer; selection needs policy. |
| Resource budget zero | REGISTERED; signature/receipt verified | REFUSED/UNKNOWN | UNKNOWN | SCITT cannot repair bounded inability to check. |

## Validation record

- Focused SCITT suite: **36 passed**.
- Full repository suite: **279 passed, 4 skipped**.
- `python scripts/check_presentation.py`: **OK**.
- `python -m compileall -q src examples/scitt_interop tests`: **OK**.
- Normative diff (`standard`, `receipts`, core verifier): **empty**.
- Base runtime dependencies: **unchanged**; SCITT dependencies are optional/pinned.
- Standard-library-only adapter import (`python -S` with `src` on `sys.path`): **OK**.
- Tracked-tree privacy/claims scan: **clean**.

## Score

- Total requirements: **248**
- Complete: **246**
- Partial: **1**
- Missing: **0**
- Justified N/A: **1**
- Blocked externally: **0**
- Applicable requirements: **247**
- Completion percentage: **99.60%**
  (`COMPLETE / applicable`; PARTIAL is not counted as complete)
