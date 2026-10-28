# Pull Request Domain Explanation Language Native Version 2 Coordinates

Pull Request Domain Explanation Language (PRDEL) native version two uses two
coordinates so selected profile bytes never authenticate themselves.

## A: implementation coordinate

The `verifier-prdel-v2-implementation-coordinate-1` coordinate is the Secure
Hash Algorithm 256-bit (SHA-256) digest of line-feed-terminated canonical
JavaScript Object Notation (JSON) containing the sorted exact executable,
checker and schema member rows. Each row binds its repository-relative path,
role, byte length and SHA-256 digest. The member denominator is fixed by the
versioned checker.

Selected profile, specification, receipt and host-selection bytes are excluded
from A. Changing executable, checker or schema bytes therefore changes A;
changing only selected profile metadata does not. Exclusion is not omission
from release review: the second coordinate binds the exact profile bytes.

## B: external release-subject coordinate

The external host supplies exact `verifier-prdel-v2-release-subject-2` JSON
bytes and separately selects B as the SHA-256 digest of those bytes. The subject
binds A, both regenerated profile digests, conservative declared metadata, an
exact local Git base/head pair, and the byte length and SHA-256 digest of one
separately supplied release description. It carries no field for its own digest.
The checker never copies, derives or defaults the expected B from candidate-
controlled bytes.

The selected base and head must resolve to their full identifiers, the base must
be an ancestor of the head, and the head must be the checkout's current head.
Every A member, selected profile and selected specification read by the checker
must be byte-identical to that head. This prevents a dirty implementation from
borrowing a committed source coordinate. The checker then invokes
`scripts/check_pr_description.py` with the exact description file, base and
commit. That production gate must pass against the commit's own tree; a matching
description digest alone receives no description credit.

Absent host subject bytes, expected B or selected description bytes remain
`UNKNOWN`. An unavailable local Git or production-description observation also
remains `UNKNOWN`. A malformed subject, changed implementation coordinate,
stale or substituted profile, foreign expected B, changed declared metadata,
foreign base/head, dirty selected member, substituted description or failing
production description gate fails. A profile change leaves A unchanged but
requires a new B and new host selection.

Host selection is a trust boundary, not a self-authenticating fact. A caller
can supply bytes and a digest, but the checker cannot prove that the caller is
an authorized human or release host. Human acceptance, package inventory,
whole-suite qualification, merge and publication remain separate gates.

## Compatibility and claim boundary

The retained version-one selection profiles and wire contracts keep their
existing meanings. A `verifier-prdel-v2-release-subject-1` blob may still be
diagnosed for its historical A/profile/metadata binding, but it remains
`UNKNOWN` for release-subject selection because it binds no source history or
description bytes. These coordinates add development-candidate binding only.
They do not establish semantic completeness, runtime correctness, model
correctness, overall safety, human acceptance or release authority.
