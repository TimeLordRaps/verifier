# Current SPACE-2.1: length-preserving logical partition migration

Status: experimental, versioned current-object objective. Verifier Standard
(VSTD) specifies the claim; this Python mechanism is one reference checker.
JavaScript Object Notation (JSON) gives canonical retained bytes, and Secure
Hash Algorithm 256-bit (SHA-256) names commitments. Offsets, lengths and
extents are bytes. Counts and checking budgets are dimensionless.

The pair `verifier-current-object-obligations-1` / `SPACE-2.1` selects one
bounded dynamics proposition for the governing question "Which transitions and
interactions can its facets undergo?". The SPACE dynamics slot names coordinate
remapping, routing table updates, memory allocation and deallocation, and
spatial migration. This objective decides a strict finite subset of that
rationale, a logical partition remap between two selected layouts, on retained
bytes only. `DOMAIN_OBLIGATIONS.md` has no SPACE row, so no numbered legacy
wording is quoted or transferred. Current `SPACE-3.1` (aligned nonoverlapping
layout) and `SPACE-4.1` (complete extent coverage) are different propositions;
none of the three supplies another.

Proposition: the independently selected exact before and after SPACE-3.1
children for the same SPACE subject both replay PASS, and the retained finite
migration map is a bijection from the before layout's logical byte partitions
onto the after layout's partitions in which every mapped after partition starts
at the map's declared byte offset and has the same byte length as its before
partition.

The parent request commits to each child's request, policy and exact
certificate bytes. The after child must select the same SPACE record and typed
collection as the parent; the before child must name the same subject and may
select an earlier record of it. Both children are replayed against the
installed `SPACE-3.1` mechanism and decided before the parent: a child that
fails to replay, a substituted child or a child `FAIL` makes the parent `FAIL`
even when the other child is `UNKNOWN`; otherwise a child `UNKNOWN` makes the
parent `UNKNOWN`. Only when both children `PASS` is the map checked against
the partitions each child retains.

Evidence has exactly `schema_version`, `before`, `after` and `migration`. Each
child is `{"request","policy","certificate"}` with the certificate in canonical
base64. A map entry is exactly `{"from","to","start_byte"}`. `FAIL` means a map
source or target is not a retained partition, a before partition is mapped
twice or not at all, two before partitions share one after partition, an after
partition has no preimage, an after partition starts elsewhere than declared,
or a mapped length changes. `UNKNOWN` means absent evidence, an `UNKNOWN`
child, or an exhausted selected limit. Malformed or substituted requests,
policies and certificates are rejected before a computational verdict.

`PASS` establishes only that the represented logical layout changed by a
length-preserving remap. It does **not** establish that any host, device or
storage allocation or deallocation happened, that bytes were copied, that a
routing table or address translation was updated, that contents stayed
isolated or did not leak, or that the after layout covers its extent. Whole
SPACE dynamics tier conformance, object-profile conformance, privacy, consent,
governance and security remain `NOT_ESTABLISHED`. The check authorizes no
scheduling, spending or publication.

The parent certificate retains both exact child certificates, requests and
policies and the map. Public release of retained contents requires separate
disclosure authority. Changed child or parent source, selected specification,
retained bytes or policy invalidates the pinned mechanism. A digest or
trust-root label is not proof that a device performed the migration. The
installed descriptor also binds `retained_selection.py`, the shared plain-value
request and policy capture helper; shared selection infrastructure does not
establish this proposition.
