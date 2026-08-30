# Verifier Standard (VSTD) artifact freeze, seal, and thaw mechanism

> **Acronyms:** American Standard Code for Information Interchange (ASCII);
> JavaScript Object Notation (JSON); Privacy-Enhanced Mail (PEM);
> Secure Hash Algorithm 256-bit (SHA-256); Secure Hash Algorithm 3 256-bit (SHA3-256);
> Unicode Transformation Format, 8-bit (UTF-8); Verifier Standard (VSTD).

**Status:** normative for artifact-control mechanism version 1

This mechanism preserves exact regular-file bytes, binds them to artifact-derived
identifiers, optionally closes the freeze with a readable Ed25519 seal, and creates
mutable descendants by copy-on-write thaw. It is not a numbered VSTD profile, receipt profile,
encryption format, archival service, correctness proof, or actor reputation system.

## 1. Distinct operations

| Operation | What it establishes when verified | What it does not establish |
|---|---|---|
| **Freeze** | The bundle's current regular-file bytes and portable paths match its manifest, and its guarded payload tree is read-only. | Durable external preservation, privileged-write prevention, correctness, freshness, or a cryptographic signer. |
| **Seal** | A carried public key verifies a signature over the exact freeze closure, and the seal identifier closes the signature-bearing envelope. | Encryption, secrecy, ownership, authorization, trusted time, signer reputation, or protection against whole-bundle substitution. |
| **Thaw** | The creation operation copied a clean sealed parent into a new mutable descendant and emitted a lineage sidecar. Later `THAWED_CLEAN` status establishes current equality only when the actual supplied parent verifies and every recorded parent coordinate agrees. | Authentication of the historical copy operation, mutation of the parent, continued equality after thaw, or a sealed descendant. |

Sealing and encryption are independent. Version 1 seals are readable and authenticated;
they do not encrypt any byte. A future encrypted container MUST still identify a separate
encryption mechanism and MUST NOT treat confidentiality as closure or correctness.

## 2. Bundle and preservation boundary

A bundle contains:

```text
bundle/
  payload                 exact file, or directory of exact files and paths
  freeze.json             VSTD-ARTIFACT-FREEZE-1 manifest
  seals/*.json            zero or more VSTD-ARTIFACT-SEAL-1 envelopes
```

The mechanism accepts regular files, directories, and empty directories. Symbolic links
and special filesystem objects fail closed. It preserves file bytes and portable relative
paths. Permissions, owners, access-control lists, timestamps, extended attributes, sparse
allocation, and filesystem-specific metadata are outside version 1. The portable
read-only guard is an observable tripwire, not an access-control boundary against a
privileged writer.

Freeze classifies the caller-supplied final source entry before dereferencing it, so a
symbolic link cannot inherit its target's artifact identity. A new bundle, thaw descendant,
or generated thaw sidecar requires an absent lexical destination: an existing file,
directory, special object, symbolic link, or dangling symbolic link refuses creation.
Exclusive file and sidecar creation narrows replacement races, but version 1 does not claim
universal race-free filesystem security against a concurrent privileged process.

“Portable” means slash-normalized relative path representation. Case sensitivity,
Unicode normalization, reserved names, and path-length limits remain properties of the
host filesystem; version 1 does not claim that every valid source tree can be materialized
unchanged on every filesystem.

The manifest inventories every file with its byte size, SHA-256, and SHA3-256 digest. A
directory entry preserves an empty directory or parent path. Identifier computation uses
canonical JSON with UTF-8, sorted object keys, no insignificant whitespace, no non-finite
numbers, and no duplicate keys. Stored objects remain readable; unknown fields fail closed.

## 3. Artifact-derived identifiers

Every version 1 identifier carries independent SHA-256 and SHA3-256 commitments:

```text
vstd-<kind>-1:sha256:<64 lowercase hexadecimal characters>:
              sha3-256:<64 lowercase hexadecimal characters>
```

`content_id` closes artifact kind, paths, byte sizes, and file digests. `artifact_id`
closes the same content plus the declared media type. `freeze_id` closes the complete
freeze manifest except its own field. The artifact therefore carries a self-consistent
identity while frozen and sealed; the identity is derived from artifact state, not from
an actor's name or standing.

Hash commitments are indexes and mutation detectors, not preservation. The bundle keeps
the exact bytes so a verifier can recompute both algorithms. If an algorithm weakens,
later evidence may add a new external commitment to the preserved historical bytes. It
MUST NOT rewrite the old manifest or claim that a digest alone retained the bytes.

## 4. Finite self-closing seal

A `VSTD-ARTIFACT-SEAL-1` envelope contains the complete seal payload, raw public key,
signature, and seal identifier. The seal payload closes the artifact, content, freeze,
exact freeze-manifest digests, key identifier, signature algorithm, and closure rule.

Let `C(x)` be version 1 canonical JSON, `E` the complete envelope, and `Sign` Ed25519:

```text
E0       = E with signature_base64 = null and seal_id = null
signature = Sign(private_key, C(E0))
E1       = E with signature_base64 = signature and seal_id = null
seal_id  = dual_digest("vstd-seal-1", C(E1))
```

Verification reconstructs `E0`, verifies the signature with the carried public key,
reconstructs `E1`, recomputes `seal_id`, and independently recomputes the freeze and
payload bytes. The two explicit holes terminate the construction: no seal-of-seal chain
is required, while a change to any closed field, signature, or identifier fails.

The carried key proves only internal signature consistency. An attacker can substitute a
whole self-consistent bundle and key. A relying party that needs continuity with an
earlier coordinate MUST supply an expected `artifact_id`, expected key identifier, or
separately verified external log/manifest entry. External anchoring is not part of
self-closure and actor identity contributes no verdict weight.

Duplicate copies of one seal deduplicate by `seal_id` and add no strength. A valid and an
invalid seal remain `CONFLICTED`; placement or multiplicity cannot erase the invalid
evidence.

## 5. Thaw and lineage

Thaw requires a cleanly verified seal. It copies the parent payload to a new writable
path and emits a `VSTD-ARTIFACT-THAW-1` sidecar beside the descendant. The sidecar records
the parent artifact, content, freeze, and seal identifiers. It is lineage metadata, not a
seal. The requested descendant and sidecar paths must both be lexically absent; thaw never
uses a preexisting symbolic link as permission to create or label its target. The parent
remains unchanged.

A sidecar's self-derived `thaw_id` establishes only internal agreement among its fields.
Sidecar-only status is `NOT_ESTABLISHED`, even when current descendant bytes match the
recorded artifact identifier. `THAWED_CLEAN` requires the actual supplied parent bundle to
verify as cleanly `SEALED`; its artifact, content, freeze, artifact-kind, and media-type
coordinates must equal the sidecar; and every sidecar seal identifier must remain valid on
that parent. Later additional valid parent seals are permitted. A conflicted parent or any
coordinate mismatch fails closed. Authoritative parent metadata—not sidecar metadata—is
used for the established descendant comparison.

`THAWED_CLEAN` means the current descendant matches that supplied, cleanly sealed parent.
`THAWED_DIRTY` means the verified parent coordinates still agree but the descendant no
longer does. Neither result proves that a verifier independently observed or authenticated
the historical copy operation. That claim requires a separately signed, logged, attested,
or otherwise mechanism-checked event. Without an expected artifact identifier, expected
key identifier, or separately verified external log coordinate, a supplied parent proves
internal parent consistency rather than external continuity.

To produce a new frozen artifact, freeze the descendant into a new bundle and bind the
sealed parent through `lineage`. This is an additive state transition; no operation edits
or erases the parent.

`bound_contexts` similarly binds the artifact identifiers of clean sealed context
bundles. It does not interpret or validate their subject matter. A sealed realm descriptor,
for example, remains only a bound declaration until a named realm or mapping verifier
checks it.

## 6. Results and artifact-first semantics

| State | Meaning |
|---|---|
| `FROZEN_UNSEALED` | Exact bytes, manifest, identifiers, and guards recomputed; no valid seal was required or established. |
| `NOT_ESTABLISHED` | A seal was required but none was established. |
| `SEALED` | Freeze, guards, and at least one seal verified with no contradictory seal. |
| `CONFLICTED` | Valid and invalid seal evidence coexist. |
| `FAIL` | A checked structural, byte, guard, seal, or external-anchor condition failed. |
| `THAWED_CLEAN` / `THAWED_DIRTY` | With an actual cleanly verified supplied parent whose exact recorded coordinates agree, a mutable descendant currently matches or differs from that parent. Historical execution of the copy remains `NOT_ESTABLISHED`. |

A clean freeze or seal can earn bounded **TRUST** in integrity and closure. It earns no
support for semantic correctness. Freezing does not stop **ROT** caused by staleness,
revocation, supersession, broken dependencies, or changed admissibility. A clean preserved
ancestor may lower mutation-related diagnostic priority, but **RUST** remains reverse
diagnostic reachability rather than innocence, guilt, or causal localization.

Realm and temporal claims follow the
[realm and time-capsule architecture](https://github.com/TimeLordRaps/verifier/blob/main/docs/REALMS_AND_TIME_CAPSULES.md). A structural seal
is atemporal at its core. It binds a realm descriptor only as context and does not prove
that realm, its clocks, mappings, physical laws, or continuous closure.

## 7. Public format and implementation

The strict combined schema is published at
[`artifact-control-1.schema.json`](https://timelordraps.github.io/verifier/schemas/artifact-control-1.schema.json).
The Python application programming interface and `vstd artifact` commands are generated
in the public reference. Ed25519 operations require the optional `seal` dependency extra;
the base package retains zero required third-party runtime dependencies.
