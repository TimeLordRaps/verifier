# Verifier Standard (VSTD)-3 implementation compatibility

> Reader aid: [concept glossary and primary precedents](../../CONCEPTS_AND_PRECEDENTS.md).

VSTD-3 is additive. It does not reinterpret earlier receipt wire formats. For
the historical filename and wire-identifier table, see
`../../../standard/WIRE_IDENTIFIERS.md`.

The currently shipped adapter boundary is centralized in
[`docs/CLAIMS_AND_LIMITS.md`](../../CLAIMS_AND_LIMITS.md#what-the-current-adapters-can-say):
host-visible metadata is not device attestation, and the virtual accelerator establishes
only its emulator-scoped claims.

## Existing receipts

- `VSTD-0.1` receipt validators keep their existing VSTD-1 wire semantics.
- `VSTD-DATA-0.1` hypergraphs remain readable as historical VSTD-Graph-1 receipts.
- `VSTD-0.2` geometry remains the frozen VSTD-2 wire surface.
- The public `validate`, `inspect`, `reproduce`, `data`, and `impact` commands retain
  their earlier behavior.

Historical receipts do not gain hardware claims merely because a VSTD-3 implementation
reads them.

## Additive hypergraph values

VSTD-3 adds hardware/provider artifact types and discovery, attestation, execution,
accounting, anchoring, and evidence-binding transformation types. Readers that reject
unknown enum values should upgrade before reading a hypergraph containing VSTD-3
hardware nodes. Earlier graphs containing only earlier values round-trip unchanged.

## Attaching hardware evidence to a run

1. Validate the VSTD-3 receipt with all required key resolvers.
2. Identify pre-existing output artifact IDs in the VSTD-DATA graph.
3. Call `attach_vstd3_receipt` with those IDs or record them in
   `provenance_artifact_ids`.
4. Validate graph structure and acyclicity.
5. Re-run blast-radius and relevant provenance policies.

The composition is transactional. A missing output, invalid receipt, overclaimed
`PASS`, collision, structural error, or cycle leaves the original graph unchanged.

## No automatic claim upgrade

Host-observed inventory stays host-observed. Provider evidence stays provider evidence.
Firmware measurement stays distinct from execution evidence. Existing declared
execution records are not converted into device attestation without new evidence.

## Schema/version dispatch

Dispatch by exact `schema_version`. VSTD-3 receipts use the frozen `VSTD-3.0` wire identifier. Unknown versions
must fail closed. Do not guess a compatible decoder from field similarity.
