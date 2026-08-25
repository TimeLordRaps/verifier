# Adjacent standards interoperability matrix

> **Status:** non-normative scope control. SCITT is the primary interoperability
> target. This matrix identifies mechanisms VSTD should reuse rather than reinvent.

| Standard/system | What it already supplies | Reuse | Reference | Consume | Do not replace |
|---|---|---|---|---|---|
| [IETF SCITT RFC 9943](https://datatracker.ietf.org/doc/html/rfc9943) + [COSE Receipts RFC 9942](https://datatracker.ietf.org/doc/html/rfc9942) | COSE Signed Statements, issuer/subject binding, registration policy, transparency services, VDS guarantees, portable inclusion/consistency receipts. | Signed Statement and Receipt envelopes, VDS identifiers, and attachment rules. | Exact RFCs, selected VDS profile, TS policy, and keys. | Independently verified registration/inclusion as narrowly typed transparency evidence. | Signature envelopes, transparency services, VDS registries, receipt attachment, or registration APIs. |
| [in-toto specification v1.0](https://in-toto.io/docs/specs/) | Signed layouts, authorized functionaries, step links, materials/products, artifact rules, and supply-chain verification. | Native layouts, links, and artifact-rule processing. | Exact metadata bytes, specification version, functionary keys, and layout policy. | Native verification result and bound material/product digests. | Software-supply-chain step authorization, layout processing, or artifact-rule semantics. |
| [SLSA v1.2](https://slsa.dev/spec/v1.2/provenance) | Build/source provenance, attestation predicates, build levels, producer expectations, and verification procedures. | SLSA predicates and verification-summary conventions. | Claimed track/level, predicate version, producer, and verification procedure. | Schema-valid provenance and native verifier output. | SLSA levels, build-platform threat model, provenance schemas, or ecosystem expectations. |
| [Sigstore](https://docs.sigstore.dev/) / [Rekor](https://docs.sigstore.dev/logging/overview/) | Identity-bound signing, short-lived certificates, signature transparency, inclusion proofs, and public-log monitoring. | Sigstore bundles and native verification workflow. | Fulcio/Rekor trust roots, certificate identity policy, integration time, and log coordinates. | Verified signature/certificate/Rekor results and exact bundle bytes. | Fulcio, Rekor, identity federation, keyless signing, or transparency monitoring. |
| [C2PA 2.4](https://spec.c2pa.org/specifications/) | Content Credentials, signed manifests, hard/soft asset bindings, assertions, ingredient/action history, validation statuses, and trust lists. | Native manifest, assertion, ingredient, and asset-binding semantics. | Exact C2PA version, validation algorithm, trust list, asset, and manifest. | Native validation output and exact asset/manifest bytes for bounded media claims. | Media embedding, content binding, assertion vocabulary, or the C2PA trust model. |
| [W3C PROV-O Recommendation](https://www.w3.org/TR/prov-o/) | Interoperable provenance vocabulary for entities, activities, agents, and relations in RDF/OWL. | PROV entity/activity/agent relations where semantic-web interchange is required. | PROV-O Recommendation, ontology IRIs, serialization, and namespaces. | Identified PROV graphs under an explicit mapping and completeness policy. | General provenance ontology, RDF, or OWL semantics. |
| [SPDX 3.0.1](https://spdx.github.io/spdx-spec/) | BOM data model and serializations for software, builds, AI models, datasets, vulnerabilities, licenses, relationships, provenance, and integrity. | SPDX element and relationship vocabulary. | Exact model/specification version, profile, namespace, and serialization. | Schema-valid SPDX elements, relationships, and native validation output. | SBOM/AI BOM vocabulary, license conclusions, vulnerability model, or SPDX conformance. |
| [IETF RATS Architecture RFC 9334](https://datatracker.ietf.org/doc/html/rfc9334) | Attester, Verifier, Relying Party roles; Evidence, Endorsements, Reference Values, Attestation Results, appraisal policy, and freshness models. | Standard attestation roles and trust terminology. | Appraisal policy, trust anchors, freshness method, endorsements, and reference values. | Native Attestation Results and the verifier's declared trust coordinates. | Remote-attestation architecture, freshness methods, role semantics, or authorization decisions. |
| [Entity Attestation Token RFC 9711](https://www.rfc-editor.org/rfc/rfc9711.html) | CWT/JWT attestation claim framework, profiles, submodules, and authenticity/integrity protection. | Registered EAT claim and profile semantics. | Exact EAT profile, token envelope, trust anchors, and verification algorithm. | Profile-validated EAT claims or Attestation Results. | EAT registries, token envelopes, device profiles, or key protection. |
| [CoRIM draft-ietf-rats-corim-11](https://datatracker.ietf.org/doc/html/draft-ietf-rats-corim-11) | Active RATS WG Last Call work on CBOR reference integrity manifests, endorsements, and reference values. | CoRIM structures only under the selected revision. | Exact active draft revision and its evolving registries. | Native validation output and identified reference values under an explicit policy. | Reference-value or endorsement manifest schema. |
| [DSSE](https://github.com/secure-systems-lab/dsse/blob/master/envelope.md) and in-toto Attestation Framework | Payload-type-bound signing envelope and generic statement/predicate convention. | DSSE when an upstream ecosystem already emits it. | Payload type, envelope specification, signing keys, and predicate type. | Native signature-verification output and exact envelope bytes. | Another JSON signing envelope; SCITT interoperability uses COSE as specified by RFC 9943. |

## Design rule

VSTD is the standard domain language and general operator/result class through which
orchestrated native verifiers, proof engines, and evidence substrata can expose
interoperable claim boundaries and portable results. A loss-declared adapter records
native bytes, version/profile, trust roots, native result, VSTD claim coordinates,
and any omitted or transformed semantics. VSTD does not replace the native engine
or reinterpret its domain semantics, and it must not translate a native success into
a stronger VSTD result than the native evidence and VSTD checker jointly support.

The result should be a smaller VSTD architecture:

- SCITT/Sigstore provide transparency and signing where appropriate;
- in-toto/SLSA/SPDX provide software-supply-chain vocabulary and evidence;
- C2PA provides media provenance and content binding;
- W3C PROV provides general provenance interchange;
- RATS/EAT/CoRIM provide attestation roles, tokens, endorsements, and reference
  values;
- VSTD standardizes the bounded claim boundary, portable result, UNKNOWN, and
  refutation semantics across selected native evidence.
