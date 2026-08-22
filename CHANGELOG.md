# Changelog

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
