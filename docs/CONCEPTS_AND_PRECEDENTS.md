# Concept guide and intellectual precedents

**Status:** non-normative reader aid

VSTD did not arise in a vacuum, but it also does not inherit another system's
guarantees merely by citing it. This guide separates two kinds of link:

1. **Orientation links** point to Wikipedia for a quick definition. The links use
   ordinary Markdown title text, which some browsers expose as a small hover tooltip.
   GitHub does not run Wikipedia's Page Previews code, so a full infobox-style hover card
   is not portable in repository Markdown.
2. **Primary references** point to standards, specifications, or original papers. These
   establish the neighboring precedent described here. They do not prove that VSTD is
   correct, adopted, interoperable, accredited, or conformant to the referenced system.

When an orientation summary and a primary source differ, use the primary source. When a
primary source and a VSTD requirement differ, the VSTD document controls VSTD conformance
and the difference must remain explicit.

## Orientation glossary

| Concept | Quick orientation | How VSTD uses or bounds it |
|---|---|---|
| Assurance | [Information assurance](https://en.wikipedia.org/wiki/Information_assurance "Wikipedia orientation; not a VSTD authority") | VSTD reports evidence-bounded results, not universal confidence or institutional accreditation. |
| Layered controls | [Defense in depth](https://en.wikipedia.org/wiki/Defense_in_depth_%28computing%29 "Wikipedia orientation; not a VSTD authority") | The analogy is multiple failure classes. VSTD adds the stricter rule that evidence for one layer never supplies another. |
| Fail-closed decisions | [Fail-safe](https://en.wikipedia.org/wiki/Fail-safe "Wikipedia orientation; not a VSTD authority") | Missing or exhausted evidence stays `UNKNOWN`, `INDETERMINATE`, or `UNSUPPORTED`; it does not become a pass. |
| Trusted computing base | [Trusted computing base](https://en.wikipedia.org/wiki/Trusted_computing_base "Wikipedia orientation; not a VSTD authority") | Every result must expose the mechanism and trust roots on which it depends. |
| Zero trust | [Zero trust architecture](https://en.wikipedia.org/wiki/Zero_trust_architecture "Wikipedia orientation; not a VSTD authority") | VSTD borrows no product architecture wholesale; it uses explicit verification rather than identity or location as an automatic correctness signal. |
| Canonicalization | [Canonicalization](https://en.wikipedia.org/wiki/Canonicalization "Wikipedia orientation; not a VSTD authority") | Stable fields need one declared byte representation before hashing. VSTD's formats are not thereby RFC 8785 implementations. |
| Content addressing | [Content-addressable storage](https://en.wikipedia.org/wiki/Content-addressable_storage "Wikipedia orientation; not a VSTD authority") | Artifact and receipt coordinates bind declared bytes through digests; a digest alone does not establish origin or truth. |
| Cryptographic digest | [Cryptographic hash function](https://en.wikipedia.org/wiki/Cryptographic_hash_function "Wikipedia orientation; not a VSTD authority") | Hash observations can establish byte identity within an algorithm and observation boundary, not semantic correctness. |
| Provenance | [Data provenance](https://en.wikipedia.org/wiki/Data_provenance "Wikipedia orientation; not a VSTD authority") | VSTD-Graph records declared entities, transformations, and ancestry while preserving incomplete or unauthenticated history as such. |
| Hypergraph | [Hypergraph](https://en.wikipedia.org/wiki/Hypergraph "Wikipedia orientation; not a VSTD authority") | N-ary transformation edges preserve many-input and many-output structure without flattening it into ambiguous binary links. |
| Attestation | [Attestation](https://en.wikipedia.org/wiki/Attestation "Wikipedia orientation; not a VSTD authority") | VSTD-3 records who or what supplied evidence, the mechanism used, and the resulting evidence ceiling. |
| Trust root | [Trust anchor](https://en.wikipedia.org/wiki/Trust_anchor "Wikipedia orientation; not a VSTD authority") | A declared root is an explicit dependency and stopping boundary, not evidence that the root is honest. |
| Reproducibility | [Reproducibility](https://en.wikipedia.org/wiki/Reproducibility "Wikipedia orientation; not a VSTD authority") | VSTD binds the exact mechanism, inputs, environment, and equivalence relation required by the claim rather than treating the word as self-defining. |
| Reproducible build | [Reproducible builds](https://en.wikipedia.org/wiki/Reproducible_builds "Wikipedia orientation; not a VSTD authority") | Independently recreating identical artifacts is an important special case of portable checking, not a proof of every property of the artifact. |
| Falsifiability | [Falsifiability](https://en.wikipedia.org/wiki/Falsifiability "Wikipedia orientation; not a VSTD authority") | VSTD-4 requires an explicit, bounded way for an outside checker to refute the exact claim. It does not turn Popper's philosophy into a software theorem. |
| Proof-carrying artifact | [Proof-carrying code](https://en.wikipedia.org/wiki/Proof-carrying_code "Wikipedia orientation; not a VSTD authority") | The engineering precedent is that an untrusted producer can ship a result with a smaller independently checkable certificate under a declared policy. |
| SAT | [Boolean satisfiability problem](https://en.wikipedia.org/wiki/Boolean_satisfiability_problem "Wikipedia orientation; not a VSTD authority") | The reference subset encodes finite admission questions; SAT success establishes only the encoded formula. |
| CNF | [Conjunctive normal form](https://en.wikipedia.org/wiki/Conjunctive_normal_form "Wikipedia orientation; not a VSTD authority") | VSTD's bounded policy encodings use finite CNF and do not equate arbitrary CNF with 3-SAT. |
| Resolution | [Resolution](https://en.wikipedia.org/wiki/Resolution_%28logic%29 "Wikipedia orientation; not a VSTD authority") | Clausal refutations provide checkable evidence for an unsatisfiable result within the implemented proof format. |
| Unit propagation | [Unit propagation](https://en.wikipedia.org/wiki/Unit_propagation "Wikipedia orientation; not a VSTD authority") | The minimal trusted checker validates the supported reverse-unit-propagation certificate path rather than trusting the producer's solver. |
| Three-valued result | [Three-valued logic](https://en.wikipedia.org/wiki/Three-valued_logic "Wikipedia orientation; not a VSTD authority") | `UNKNOWN` is a first-class refusal to overstate, not a Boolean false and never a pass. VSTD's statuses are not claimed to implement one historical three-valued logic. |
| Append-only transparency | [Certificate Transparency](https://en.wikipedia.org/wiki/Certificate_Transparency "Wikipedia orientation; not a VSTD authority") | Immutable receipts and additive corrections share an auditability goal with append-only logs; VSTD is not a Certificate Transparency implementation. |
| Update freshness | [The Update Framework](https://en.wikipedia.org/wiki/The_Update_Framework "Wikipedia orientation; not a VSTD authority") | Staleness, rollback, revocation, and key compromise are separate from content integrity and require explicit current-state evidence. |
| Semantic versioning | [Semantic Versioning](https://en.wikipedia.org/wiki/Software_versioning#Semantic_versioning "Wikipedia orientation; not a VSTD authority") | Repository releases use semantic versions independently of the VSTD object and Graph layer numbers. |
| Object language and metalanguage | [Metalogic](https://en.wikipedia.org/wiki/Metalogic "Wikipedia orientation; not a VSTD authority") | VSTD uses this only as a design analogy for examining a verification surface; it does not claim that every adjacent layer is a formal metalanguage. |
| Undefinability of truth | [Tarski's undefinability theorem](https://en.wikipedia.org/wiki/Tarski%27s_undefinability_theorem "Wikipedia orientation; not a VSTD authority") | The ladder expressly does not derive its architecture or observational limits from Tarski's theorem. |

## Primary reference map

| VSTD design seam | Primary or official reference | Relevant precedent and explicit limit |
|---|---|---|
| Separate failure controls and fail-safe defaults | Saltzer and Schroeder, [*The Protection of Information in Computer Systems*](https://web.mit.edu/Saltzer/www/publications/pubs.html) (1975) | Classic security-design principles include fail-safe defaults, complete mediation, separation of privilege, least privilege, and least common mechanism. They motivate separating failure surfaces; they do not derive VSTD's five layers. |
| Security-assurance components and packages | Common Criteria, [Part 3: Security assurance components](https://www.commoncriteriaportal.org/files/ccfiles/CC2022PART3R1.pdf) (CC:2022 Revision 1) | Established precedent for decomposing assurance into named components and packages. VSTD is not Common Criteria, accredited evaluation, or an Evaluation Assurance Level. |
| Canonical JSON as a cryptographic wire input | IETF Independent Stream, [RFC 8785: JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785.html) | Shows why cryptographic operations over JSON require invariant representation. VSTD uses its own declared canonicalization rules and must not claim RFC 8785 conformance unless a format actually implements it. |
| Provenance entities, activities, and agents | W3C, [PROV-DM: The PROV Data Model](https://www.w3.org/TR/prov-dm/) | Standardized vocabulary and constraints for interoperable provenance. VSTD-Graph's artifact and transformation model is adjacent, not a PROV implementation or complete history claim. |
| Supply-chain step and artifact attestations | [in-toto specification v1.0](https://in-toto.io/docs/specs/) and [SLSA v1.2](https://slsa.dev/spec/v1.2/) | Established formats and levels for materials, products, builders, steps, and provenance. VSTD may bind their outputs as evidence but does not manufacture their authorization or assurance level. |
| Release preservation and provenance integrity | NIST, [SP 800-218: Secure Software Development Framework 1.1](https://doi.org/10.6028/NIST.SP.800-218) | Practices PS.3.1 and PS.3.2 cover archiving releases, maintaining provenance, protecting its integrity, and enabling recipient verification. This is operational precedent, not VSTD certification. |
| Independent recreation of artifacts | Reproducible Builds, [formal definition](https://reproducible-builds.org/docs/definition/) | Defines the source, environment, instruction, and artifact relationship needed for bit-for-bit recreation. VSTD permits other explicitly declared equivalence relations and does not infer truth from reproducibility alone. |
| Producer-supplied, consumer-checked certificates | Necula, [*Proof-Carrying Code*](https://doi.org/10.1145/263699.263712) (POPL 1997) | Primary precedent for an untrusted producer supplying a proof checked under a defined policy by the consumer. VSTD generalizes the receipt pattern but does not inherit PCC's safety theorem. |
| Checkable SAT refutations | Wetzler, Heule, and Hunt, [*DRAT-trim: Efficient Checking and Trimming Using Expressive Clausal Proofs*](https://www.cs.cmu.edu/~mheule/publications/drat-trim.pdf) (2014) | Demonstrates independently checking unsatisfiability proofs rather than trusting a SAT solver's answer. VSTD's implemented certificate is a narrower declared RUP path, not arbitrary DRAT. |
| Explicit indeterminate solver results | [SMT-LIB Standard 2.7](https://smt-lib.org/papers/smt-lib-reference-v2.7-r2025-04-09.pdf) | The standard response grammar includes `sat`, `unsat`, and `unknown`. VSTD's richer status vocabulary is independently defined, but the refusal to fabricate a Boolean answer has established solver precedent. |
| Append-only evidence and independently detectable equivocation | IETF, [RFC 9162: Certificate Transparency Version 2.0](https://www.rfc-editor.org/rfc/rfc9162.html) | Merkle inclusion and consistency proofs support auditing an append-only log, while the RFC also names split-view limitations. VSTD's additive history is analogous but not a CT log. |
| Freshness, rollback, freeze, and key-compromise boundaries | [The Update Framework specification](https://theupdateframework.github.io/specification/latest/) | Separates current-version metadata, expiration, delegated roles, and compromise recovery from artifact bytes. VSTD does not implement TUF, but shares the requirement that old authentic data is not automatically current data. |

## How to cite these precedents

Use language such as:

- "VSTD's portable-certificate design is adjacent to proof-carrying code."
- "VSTD-Graph overlaps W3C PROV, in-toto, and SLSA at the provenance boundary."
- "The refusal to convert resource exhaustion into a false result has precedent in the
  `unknown` response of SMT-LIB."

Do not write:

- "Saltzer and Schroeder prove the VSTD ladder."
- "VSTD implements PROV, SLSA, in-toto, TUF, Common Criteria, or Certificate
  Transparency," unless separately demonstrated by a named conformance mechanism.
- "These citations establish VSTD's security, completeness, adoption, or novelty."

The point of the map is traceable intellectual context: which established problem a VSTD
rule resembles, where the design deliberately differs, and what remains original project
architecture rather than inherited authority.
