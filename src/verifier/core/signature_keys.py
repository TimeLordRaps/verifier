"""Bounded public-key admission for Ed25519 signature consumers.

Ed25519 is the Edwards-curve digital signature algorithm with a 255-bit field.
This standard-library screen rejects noncanonical and small-order encodings;
the optional cryptographic backend still verifies each signature. Admission
does not prove full subgroup membership, private-key custody or authority.
"""
from __future__ import annotations

_FIELD_PRIME = 2**255 - 19
# Encoded small-order y coordinates, with either sign bit. Reference:
# https://github.com/jedisct1/libsodium/blob/1.0.18/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c
_SMALL_ORDER_Y = frozenset((0, 1, _FIELD_PRIME - 1,
    2707385501144840649318225287225658788936804267575313519463743609750303402022,
    55188659117513257062467267217118295137698188065244968500265048394206261417927))


def admit_ed25519_public_key(raw: bytes) -> bytes:
    """Require 32 plain bytes and refuse known degenerate point encodings.

    The lower 255 bits encode y, a dimensionless field element. This function
    operates only on public data and implements no signing or signature math.
    """
    if type(raw) is not bytes or len(raw) != 32:
        raise ValueError("Ed25519 public key requires 32 immutable bytes")
    y = int.from_bytes(raw, "little") & (2**255 - 1)
    if y >= _FIELD_PRIME or y in _SMALL_ORDER_Y:
        raise ValueError("Ed25519 public key has a noncanonical or small-order encoding")
    return raw
