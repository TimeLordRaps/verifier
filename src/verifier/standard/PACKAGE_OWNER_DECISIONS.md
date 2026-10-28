# Package owner-decision admission

The package self-polish gate may consume one separately selected owner policy
and one decision envelope. Both byte strings require independent Secure Hash
Algorithm 256-bit (SHA-256) pins.
The gate never creates keys, chooses an owner, or treats candidate defaults as
adopted merely because the candidate ledger is structurally valid.

The policy configures one Ed25519 public key, owner identifier, policy revision,
validity interval, and maximum decision age. The signed payload binds the exact
candidate selection digest, source-coordinate digest, policy identity, and all
110 owner-decision subjects. Cross-kind decisions explicitly adopt the proposed
mapping; per-kind questions explicitly adopt the proposed default. Missing,
partial, stale, substituted, malformed, or incorrectly signed selections do not
produce adoption.

`PASS` is relative to the host-selected and digest-pinned configured-key policy.
It authenticates the exact statement only. It does not prove personhood, legal
authority, candidate truth, normative closure, all-kind corrigibility, release,
or deployment authority. Without selected policy and envelope bytes, the state
is `NOT_SELECTED`.
