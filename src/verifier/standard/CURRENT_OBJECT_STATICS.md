# Current OBJECT-3.1: canonical retained collection statics

Status: experimental, versioned current-object objective. Verifier Standard
(VSTD) specifies the claim; this Python mechanism is one reference checker.
JavaScript Object Notation (JSON) gives canonical retained bytes, Unicode
Transformation Format, 8-bit (UTF-8) is the only admitted text encoding, and
Secure Hash Algorithm 256-bit (SHA-256) names commitments. Record sizes are
bytes. Payload depth, value counts, reference counts and checking budgets are
dimensionless.

The pair `verifier-current-object-obligations-1` / `OBJECT-3.1` selects a
bounded **static byte-level** proposition over one finite collection of
namespace records. The request selects an OBJECT subject identifier and record
digest, the collection commitment of `NAMESPACE_OBJECTS.md`, and five declared
inclusive structural bounds: record count, bytes per record, payload depth,
payload JSON values and operand references. Each declared bound may only be at
or below the namespace record bound (4096 records, 8 MiB per record, depth 64,
10000 values, 4096 references); an out-of-range or unknown bound is rejected
before replay.

## Exact proposition

Every retained record is at most the declared byte bound; its SHA-256 digest
equals its retained address; addresses and identifiers are unique; its bytes
are valid UTF-8, strict and canonical JSON that reconstruct exactly one
admitted namespace record whose digest is that address; record count, payload
depth, payload value count and operand reference count are within the declared
inclusive bounds; the records recompute the selected collection commitment;
and the selected subject is the OBJECT record with the selected digest.

Canonical JSON means sorted keys, no insignificant whitespace and American Standard Code for Information Interchange (ASCII)
escaping of every non-ASCII character. Strict JSON rejects duplicate members
and non-finite numbers. Payload depth counts nesting steps below the payload
root, which is depth zero. The value count includes the root and every nested
array, object, string, number, boolean or null value; member names are not
counted. The retained evidence is one canonical JSON object listing each record
as its address and canonical base64 bytes, so the exact record bytes and not a
re-serialised parse are what the mechanism checks.

## Verdicts

`PASS` sets `canonical_collection_statics=PASS`. Noncanonical formatting,
unescaped non-ASCII text, invalid UTF-8, a duplicate member, an inadmissible
kind, an address that is not the digest of its bytes, a repeated address, a
repeated identifier, an exceeded declared bound, a differing collection
commitment or a subject that is not the selected OBJECT record is `FAIL`.
Missing retained evidence or an exhausted operation or item budget is
`UNKNOWN`. A malformed request, unsupported policy, substituted request or
policy, or any altered certificate byte raises `ObjectStaticsError` and is
`REJECTED` before replay.

## How this differs from neighbouring objectives

- `OBJECT-1.1` reconstructs **one** record and its versioned address; it does
  not inspect a collection, does not test byte canonicality of several
  records, does not check uniqueness, and declares no structural bounds.
- `OBJECT-1.2` decides typed composition: operand roles, kinds and acyclic
  dependencies. `OBJECT-3.1` does not resolve or type any operand and keeps
  `typed_composition` and `operand_resolution` `NOT_ESTABLISHED`.
- `OBJECT-8.1` decides signed namespace-admission governance. `OBJECT-3.1`
  checks no signature, authority or revocation.
- `GRAPH-3.1` decides statics of a typed GRAPH; `OBJECT-3.1` is kind-neutral
  apart from requiring the selected subject to be an OBJECT record.

## Exclusions

`PASS` does not establish typed composition or operand resolution, payload
meaning, truth, authorship or provenance, revision history, address closure,
receipt issuance, the whole OBJECT statics tier, or object-profile
conformance. `typed_composition`, `operand_resolution`, `payload_truth`,
`whole_object_statics` and `object_profile_conformance` are always
`NOT_ESTABLISHED`. Privacy, consent, governance and security are not claimed.
A digest assumes collision resistance; it is not authority or authentication.

The certificate retains every record byte and its result. Retention may
disclose payload contents; local checking grants no permission to publish it.
A changed mechanism source, namespace source, `NAMESPACE_OBJECTS.md` or this
specification changes the mechanism digest and requires policy readmission.
