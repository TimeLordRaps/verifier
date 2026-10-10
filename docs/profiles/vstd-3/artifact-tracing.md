# Experimental hardware artifact tracing

> **Acronyms:** hash-based message authentication code (HMAC); identifier (ID);
> Secure Hash Algorithm 256-bit (SHA-256); Verifier Standard (VSTD).

**Status:** experimental, additive sidecar; not part of the frozen `VSTD-3` receipt
wire format and not a VSTD-3 conformance requirement.

## Bounded purpose

The experimental hardware tracer can establish this exact proposition:

> These final post-embedding artifact bytes contain the extracted marker and match the
> declared VSTD-3 receipt, execution, topology, logical-device, physical-device, and
> runtime-measurement coordinates under the configured carrier and authentication key.

The binding does not identify a natural person or establish authorship, malicious
intent, guilt, correctness, authorization, or the absence of untraced artifacts. A
`QUARANTINE_FOR_REVIEW` recommendation is a containment signal for an external policy;
it does not authorize deletion, process termination, account action, accusation, or
retaliation.

This is confidentiality-aware tracing, not confidentiality enforcement. Permission
does not establish knowledge, and withholding direct access does not establish that
information cannot be inferred. The sidecar therefore contains no raw marker, secret
key, person identifier, private artifact content, or natural-person attribution. Its
artifact digest, coordinate digests, carrier ID, entropy-provider ID, and key ID can
still be correlating metadata and require an explicit disclosure and retention policy.

## Exact construction

1. An injected artifact-specific carrier embeds a fresh 32-byte marker.
2. The carrier must re-extract the exact marker before issuance continues.
3. SHA-256 hashes the final post-embedding artifact bytes.
4. HMAC-SHA256 authenticates a domain-separated canonical payload containing the
   marker, final artifact digest and byte length, hardware/runtime coordinate, carrier
   ID, entropy-provider ID, opaque key ID, format ID, and limitations.
5. The HMAC remains in a detached sidecar. The sidecar is not included in the artifact
   bytes it hashes.

The marker is an unlinkable random token only to the extent supplied markers are fresh
and unpredictable. HMAC-SHA256 provides computational authentication; neither mechanism
establishes information-theoretic or “entropic” security.

The reference library supplies a system-random marker source and a carrier-neutral
interface. It deliberately ships no generic append-bytes carrier and makes no claim of
steganographic concealment. A production carrier needs a format-specific review because
embedding can invalidate signatures, deterministic builds, archives, executable
formats, media decoders, and application checksums.

## Results and response

| Result | Exact meaning | Recommended action |
|---|---|---|
| `MATCH` | Final bytes, declared coordinate, extracted marker, carrier, and HMAC agree under the resolved key. | `NONE`; downstream policy may continue its other checks. |
| `MISMATCH` | After sidecar authentication succeeds, at least one directly comparable bound value contradicts it; or the supplied key produces an authentication-code mismatch. | `QUARANTINE_FOR_REVIEW`. |
| `UNKNOWN` | Extraction capability, marker, key resolver, or key material is unavailable or uninterpretable. | `QUARANTINE_FOR_REVIEW`; do not guess a clean result. |

A match says nothing about whether the artifact is beneficial, safe, authorized, or
free of untraced inputs. A mismatch localizes a binding contradiction, not an actor.
Unauthenticated sidecar fields are not accepted as evidence of contradiction: missing
authentication capability preserves `UNKNOWN` even when those fields appear not to
match the supplied artifact.

## Carrier and entropy-provider boundary

Carriers and entropy providers are injected explicitly. The public implementation does
not probe local filesystems, auto-discover providers, or silently fall back to an
unreviewed mechanism. Provider failure aborts issuance without returning modified
artifact bytes.

No external experimental entropy mechanism is registered as a provider. A future
adapter requires separate evidence for unpredictable output under its declared threat
model, uniqueness and reuse behavior, process-fork behavior, state rollback, seed and
key custody, cross-platform determinism, and fail-closed errors. Its security claim must
remain no stronger than those demonstrated properties.

## Reproduction boundary

The experimental binding is portable canonical JavaScript Object Notation (JSON), but
cross-platform comparison still depends on both implementations preserving the exact
artifact bytes and implementing the same carrier extraction and canonicalization. A
passing reference test on one operating system is not independent interoperability
evidence.
