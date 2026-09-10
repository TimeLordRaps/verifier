# Artifact-network interoperability fixture

> **Terminology:** JavaScript Object Notation (JSON); Request for Comments (RFC);
> Verifier Standard (VSTD).

`canonical-wire-fixture.json` is a deterministic, non-secret specimen for
implementing the experimental VSTD artifact-network wire in another runtime.
It fixes exact canonical bytes, digests, unpadded RFC 4648 base64url key and
signature encoding, and an Ed25519 signature payload.

## Build and exercise a complete local silo

Install the optional cryptographic dependency and materialize the checked-in
signed specimen at an absent destination:

```console
python -m pip install ".[seal]"
python examples/artifact-network/build_specimen.py built-silo
```

The builder uses only public artifact-network interfaces. It validates the
canonical transfer, signature, exact object closure, assessment receipt, and
authority model before writing `built-silo`. Its JSON output names the exact
commit and head paths. The following shell-neutral placeholders mean the
`commit_path` and `head_path` values printed by the builder:

```console
vstd network inspect built-silo built-silo/<commit_path> --head built-silo/<head_path>
vstd network diff built-silo/<commit_path> built-silo/<commit_path>
vstd network clone built-silo cloned-silo
vstd network compose --silo built-silo built-silo/<commit_path>
```

Expected boundaries are significant: self-diff has no path changes; clone
rebuilds the exact retained snapshot; and member-only composition returns
`NOT_ADMISSIBLE` with composition completeness and composed authority agency
`UNKNOWN`, because no independently assessed composite silo was supplied.
Remove the two generated directories before rerunning because every destination
must initially be absent.

Rebuild or check it with:

```console
python scripts/build_artifact_network_fixture.py --write
python scripts/build_artifact_network_fixture.py
```

The fixed signing seed is public test material and must never identify a real
publisher. Passing the fixture establishes encoding agreement only—not artifact
correctness, semantic completeness, authorization, reputation, independent
operation, or compatibility with a deployed service.

## Experimental proposition transfer

`canonical-proposition-transfer-fixture.json` contains eighteen synthetic cases
for the first registered cross-artifact rule: canonical finite-set union.
The native `verifier.interoperability.proposition_transfer` module checks actual
source sets, their declared bounds, exact target union, and target bounds
separately. Its portable receipt is a recomputable semantic record, not an
execution-identity or authority receipt. See
[`PROPOSITION_TRANSFER.md`](../../standard/PROPOSITION_TRANSFER.md).

```console
python scripts/build_proposition_transfer_fixture.py --write
python scripts/build_proposition_transfer_fixture.py
```

The generator checks hand-specified result summaries before recording receipts.
The independent hub implementation must reproduce the complete canonical bytes,
including negative and unknown results. Existing generic graph dependencies are
not upgraded by this fixture. Finite inventories do not establish real-world
completeness, self-derivation, or preservation of authority axiom agency.
