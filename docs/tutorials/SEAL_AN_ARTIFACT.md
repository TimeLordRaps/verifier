# Seal an artifact and detect a change

> **Acronyms:** identifier (ID); Secure Hash Algorithm 3 256-bit (SHA3-256); Verifier Standard (VSTD).

This Verifier Standard (VSTD) tutorial freezes a directory, seals it, thaws a working
copy, and then changes that copy so the runtime reports a different verdict. The last two
steps matter most: a mechanism that never reports a negative result has not been shown to
detect anything.

Every command below belongs to the published `vstd artifact` surface, and none of them
executes the artifact's contents. It requires the
[released package installation](../INSTALLATION.md).

## Install the sealing extra

Sealing uses Ed25519 signatures, which come from the optional `seal` dependency:

```bash
python -m pip install "verifier-standard[seal]==1.5.0"
vstd artifact --help
```

Generate a private key with a local key tool:

```bash
openssl genpkey -algorithm Ed25519 -out ed25519-private.pem
```

The key authenticates the seal envelope. It does not identify you to anyone, and a
tutorial key should never be reused for a real publisher.

## 1. Freeze exact bytes

Create a small directory and freeze it into a bundle:

```bash
mkdir payload
printf 'latency_ms 18\n' > payload/results.txt
vstd artifact freeze payload run.vstd --media-type application/octet-stream
```

The report is `[FROZEN_UNSEALED]`, and it carries three separate identifiers. They answer
different questions, which is why there is more than one:

| Field | What it binds |
|---|---|
| `content_id` | the exact file bytes |
| `artifact_id` | those bytes together with their portable paths and kinds |
| `freeze_id` | the whole freeze manifest, including the mechanism that produced it |

Each identifier carries both a Secure Hash Algorithm 256-bit (SHA-256) digest and a
SHA3-256 digest, so a break in one hash family does not silently carry the other. The
report also names the write guard it applied, `PORTABLE_READ_ONLY_TREE`, and the
canonicalization the digests were taken over.

## 2. Seal the bundle

```bash
vstd artifact seal run.vstd --private-key ed25519-private.pem
```

The result is `[SEALED]` with a `seal_id`, a `key_id`, the carried public key, and the
signature. The `closure_rule` field states in the output itself how the seal was computed:

> canonicalize the entire envelope with `signature_base64` and `seal_id` set to null;
> verify the signature; then canonicalize with only `seal_id` null and recompute `seal_id`

That two-projection rule is what lets a seal close over itself without having to contain a
digest of itself.

Sealing is authentication and closure. It is **not** encryption; the bundle's contents stay
readable.

## 3. Thaw a working copy

```bash
vstd artifact thaw run.vstd working-copy
```

Thaw is copy-on-write: it writes a mutable descendant and leaves the sealed parent
untouched. It reports `[THAWED_CLEAN]`, records the parent's three identifiers plus its
`parent_seal_ids`, and writes a sidecar record — `working-copy.vstd-thaw.json` — next to
the destination. Later `status` calls read that sidecar; `--record` points at it explicitly
when it has moved.

```bash
vstd artifact status working-copy --parent-bundle run.vstd
```

The status report is `[THAWED_CLEAN]` with `recorded_identity_match: True`,
`verified_parent_identity_match: True`, and `parent_verification_state: SEALED`.

Two fields are worth reading before relying on any of it:

- `historical_operation: NOT_ESTABLISHED` — current equality does not prove the copy
  actually happened at some past moment.
- `external_anchor_state: NOT_CHECKED` — no external log was supplied, so none was
  consulted.

The runtime prints both as warnings rather than leaving them implied. It reports what it
checked and stays silent about what it did not.

## 4. Change the copy

Edit the descendant and ask the same question again:

```bash
printf 'latency_ms 7\n' > working-copy/results.txt
vstd artifact status working-copy --parent-bundle run.vstd
```

The verdict becomes `[THAWED_DIRTY]`, with `recorded_identity_match: False` and
`verified_parent_identity_match: False`. The `observed_artifact_id` no longer equals the
`parent_artifact_id`, and the command exits `1`.

This is the step that gives the previous three their meaning.

## 5. State an expectation the bundle cannot meet

A seal establishes internal consistency: the envelope agrees with itself and with the key
it carries. That alone cannot detect substitution of a whole bundle, because a substituted
bundle is internally consistent too. Supplying an identifier from outside the bundle is
what closes that gap:

```bash
vstd artifact verify run.vstd --expected-artifact-id not-the-right-coordinate
```

The report is `[FAIL]` with `external_anchor: MISMATCH` and the error
`artifact_id does not match the expected external coordinate`; the command exits `1`.
Note that `freeze_valid` and `guard_valid` are still `True` — the bundle is intact, and it
is simply not the one you asked for. Rerun with the `artifact_id` printed in step 1 and the
same command reports `[SEALED]` with `external_anchor: ARTIFACT_ID_MATCHED` and exits `0`.

`--expected-key-id` does the same job for the signing key, and `--freeze-only` accepts a
clean freeze without claiming seal-backed identity.

## Exit status

| Situation | Reported | Exit |
|---|---|---|
| freeze, seal, or verify is clean | `[FROZEN_UNSEALED]` or `[SEALED]` | `0` |
| descendant matches its parent | `[THAWED_CLEAN]` | `0` |
| descendant has diverged | `[THAWED_DIRTY]` | `1` |
| a supplied expectation is unmet | `[FAIL]` | `1` |

The nonzero exits make these commands usable in a script without parsing the report. Add
`--json` to any of them for a machine-readable form.

## What this established, and what it did not

You established bounded integrity and closure over exact bytes, and you watched the
mechanism report a negative result when those bytes changed.

You did **not** establish that the number in `results.txt` is correct, that the key belongs
to any particular person or organization, that the freeze happened at a claimed time, or
that any external party retained a copy. A freeze binds bytes; it does not make them true.
For the boundary in normative form, read the
[artifact-control mechanism](../../src/verifier/standard/ARTIFACT_CONTROL.md), and for the
surrounding model read [realms and time capsules](../REALMS_AND_TIME_CAPSULES.md) and
[claims and limits](../CLAIMS_AND_LIMITS.md).

## Next

- [Publish a verification-artifact silo](PUBLISH_A_SILO.md) puts sealed records into a
  content-addressed publisher store that another party can rebuild byte for byte.
- [Your first receipt](../FIRST_RECEIPT.md) captures a computation rather than a directory.
