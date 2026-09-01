# Ecosystem boundary map

> **Acronyms:** Concise Binary Object Representation (CBOR); CBOR Object Signing and Encryption (COSE);
> Internet Engineering Task Force (IETF); World Wide Web Consortium provenance vocabulary (PROV);
> Request for Comments (RFC); Supply Chain Integrity, Transparency, and Trust (SCITT);
> Supply-chain Levels for Software Artifacts (SLSA); verifiable data structure (VDS); Verifier Standard (VSTD);
> World Wide Web Consortium (W3C).

> Reader aid: [concept glossary and primary precedents](CONCEPTS_AND_PRECEDENTS.md).

**Status:** non-normative positioning note
**Reviewed:** 2026-08-23

VSTD is designed to compose with established provenance, software-supply-chain, and
artifact-authentication systems. It does not rename their guarantees as its own and
does not claim to replace them.

VSTD supplies a common operator language for claim coordinates, evidence references,
bounds, native outcomes, assumptions, and degradation rules. Native verifiers retain
their own semantics and authority. A loss-declared adapter maps between those roles; it
does not transfer authority to VSTD, strengthen a native result, or require consumers to
adopt the producer's private orchestration logic.

| System | Its documented center of gravity | What VSTD may bind or add | What VSTD must not claim |
|---|---|---|---|
| [IETF SCITT RFC 9943](https://datatracker.ietf.org/doc/html/rfc9943) and [COSE Receipts RFC 9942](https://datatracker.ietf.org/doc/html/rfc9942) | Signed Statements, registration policy, append-only/non-equivocating transparency services, and portable VDS receipts. | Carry a complete VSTD receipt as an application payload; consume native-verified registration/inclusion as narrowly typed transparency evidence. See the [experimental crosswalk](standards/VSTD_SCITT_CROSSWALK.md). | That registration establishes computational truth, distinct actors, or that VSTD replaces COSE, a Transparency Service, VDS proof profiles, or SCITT trust policy. |
| [SLSA v1.2](https://slsa.dev/spec/v1.2/) | Levels and tracks for incrementally improving software supply-chain security, including recommended provenance and verification-summary formats. | A SLSA statement or verification summary as evidence under an explicit VSTD claim coordinate; separate refutation and degradation conditions. | That a VSTD receipt establishes a SLSA level without satisfying and assessing the relevant SLSA requirements. |
| [in-toto](https://in-toto.io/docs/getting-started/) | Signed layouts and link metadata describing authorized supply-chain steps, functionaries, materials, and products. | in-toto layout/link bytes as named evidence; graph edges that point to checked step metadata. | That VSTD re-authorizes a functionary or repairs a missing/invalid in-toto chain. |
| [Sigstore](https://docs.sigstore.dev/) | Artifact signing associated with identity, short-lived certificates, and transparency-log evidence. | Sigstore bundle, certificate identity, trust root, and verification result as explicit evidence and trust-root fields. | That a digest alone authenticates a signer, or that VSTD reference-kernel acceptance substitutes for signature and transparency-log verification. |
| [W3C PROV](https://www.w3.org/TR/prov-overview/) | A model and serializations for interoperable exchange of provenance about entities, activities, and agents. | A mapping between a declared VSTD-Graph profile and identified PROV records, with unmapped fields reported. | W3C endorsement, automatic semantic equivalence, or completeness of a provenance record. |

## Composition rule

An adapter should preserve the source system's bytes, identifiers, version, trust roots,
and native verification result. It should then state which VSTD coordinate consumes
that result and which information remains outside the mapping.

```text
native object ──native verifier──> native result
      │                                  │
      └──── preserved bytes + identity ──┴──> loss-declared adapter
                                                │
                                                ▼
                                   VSTD claim boundary + portable result
                                                │
                                                ▼
                              another verifier, framework, or relying party
```

The VSTD claim does not flow backward and strengthen the native result. If the native
verifier returns an unknown, unsupported, expired, or invalid outcome, the adapter must
preserve it rather than translating it into a clean VSTD result.

Mapping through VSTD is not automatic semantic equivalence. Every adapter must state
what was preserved, what was omitted, what was transformed, and which native
assumptions remain authoritative.

## Adapter acceptance checklist

An ecosystem adapter is not ready until it declares and tests:

1. exact accepted upstream versions and serialized receipt identifiers;
2. canonical bytes and digest rules;
3. upstream verification mechanism and trust roots;
4. field-by-field mapping, including information loss;
5. freshness and availability behavior;
6. invalid, unsupported, and unknown outcome mappings;
7. adversarial fixtures for substitution, omission, replay, and scope widening;
8. a non-endorsement statement.

No adapter is included merely to populate a compatibility list. Each adapter increases
the trusted and maintained surface and therefore needs its own evidence and tests.

The current SCITT adapter is explicitly experimental and non-normative. Its exact
claim boundary is documented in
[`standards/SCITT_SEMANTIC_BOUNDARY.md`](standards/SCITT_SEMANTIC_BOUNDARY.md).
