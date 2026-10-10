# Current TIME-3.1: strict order on one declared clock

Status: experimental, versioned current-object objective. Verifier Standard
(VSTD) specifies the claim; this Python mechanism is one reference checker.
JavaScript Object Notation (JSON) gives canonical retained bytes, and Secure
Hash Algorithm 256-bit (SHA-256) names commitments. Every `_us` value is an
integer number of microseconds on one **declared** clock. Sample counts and
checking budgets are dimensionless.

## Exact proposition

The pair `verifier-current-object-obligations-1` / `TIME-3.1` selects one
bounded TIME statics proposition: **strict monotonicity of one declared
clock's retained samples**. An independently selected exact `TIME-2.1`
request, policy and certificate are retained and replayed against the
installed child mechanism. Only a child `PASS` permits the strictness check.

`TIME-2.1` admits nondecreasing instants, so two retained samples may share an
instant. This objective is stricter: for every consecutive pair of retained
samples, in their retained order, the earlier instant must be strictly less
than the later one. An equal adjacent pair is `FAIL` here even though the
child replays `PASS`. Because the child already requires a nondecreasing
sequence inside its declared half-open span, a parent `PASS` means no two
retained samples share an instant. A single retained sample passes vacuously:
it has no consecutive pair to compare. An empty sample sequence never reaches
this check, because the child reports it `UNKNOWN`.

`PASS` means only that the selected finite retained sequence is strictly
increasing on its one declared clock. `FAIL` means the selected child failed,
did not replay, was substituted, or retained an equal adjacent pair. `UNKNOWN`
means required evidence, a passing child replay or checking capacity is
unavailable.

## Selection, evidence and replay

The parent request commits to the child request digest, child policy digest
and exact child certificate bytes, and names the same TIME subject, object
digest and complete collection digest as the child. The retained parent
evidence is one canonical record holding the child request, the child policy
and the base64 child certificate.

Errors map exactly as in `SPACE-4.1`. A refuted selection is `FAIL`: a
digest that does not match, a child naming another subject, clock, span or
coordinate, a certificate of another dependency, or a child that does not
replay. An unavailable result is `UNKNOWN`: missing evidence, a bound that is
exceeded, an `UNKNOWN` child or an exhausted budget. Malformed limits,
requests, policies and certificates are refused before a computational
verdict. One checking budget serves one evaluation: it counts every JSON
value of the retained parent evidence and then one operation per consecutive
pair compared. That count, and the `max_items` bound on every container of
the retained parent evidence, are checked before any child digest is
compared, so a substituted child under a `max_items` or operation budget too
small for that evidence is `UNKNOWN`, not `FAIL`. A retained sample count
above `max_items` is `UNKNOWN`.

Parent ceilings are 100000 operations, 4096 items, 8 MiB of evidence and a
16 MiB certificate. Evidence above the selected evidence limit is `UNKNOWN`,
except that evidence above the 8 MiB ceiling is refused at build whatever
limit is selected. A certificate that retains such evidence and reproduces
exactly still gives `UNKNOWN` at recheck, since no selected limit exceeds the
ceiling; a certificate above the selected certificate bound is refused first.
Canonical base64 decodes to at most three quarters of its length, so a child
retained within the ceiling is under 6 MiB, below the 8 MiB `TIME-2.1`
certificate bound. A larger child is subsumed by the evidence bound: it is
refused at build and gives `UNKNOWN` at recheck.

One selected instance is two certificates: the TIME-3.1 parent and the exact
TIME-2.1 child it embeds, which is owned by its TIME-2 obligation. It is not a
checker call and not a duplicate certificate. How many instances the whole
slot requires is UNKNOWN.

The installed descriptor binds this specification, `CURRENT_TIME_ORDER.md`,
`NAMESPACE_OBJECTS.md`, the child mechanism, the shared plain-value selection
helper, the bounded domain checking primitives in `domains/common.py` and the
certificate, evidence, namespace and receipt sources. A change to any of them
invalidates the pinned mechanism digest and the selected policy.

## Exclusions

Each of the following remains `NOT_ESTABLISHED` in every result, whatever the
status:

- the causal arrow: strict instants on a declared clock do not establish that
  one sample caused, or could have caused, another, and do not bind any EVENT
  to any TIME;
- clock skew, clock identity, calibration and wall-clock truth: the clock is a
  declared label, and no physical clock, shared epoch or elapsed real time is
  proved;
- relations between clocks: two clocks are never compared, ordered or
  synchronized;
- minimum spacing: a difference of one microsecond satisfies strictness, and
  no resolution, gap or rate is asserted;
- the whole TIME statics tier and object-profile conformance: this is one
  objective in that tier, not its closure;
- privacy, consent, governance and security.

Trust-root labels select a policy but authenticate no clock or observer. This
check cannot authorize scheduling, spending or publication.

## Retention and disclosure

The parent certificate retains the exact child certificate, request and
policy as evidence, plus the parent request and replay result. Its schema is
registered as a canonical certificate schema, so a request to emit it with
retained evidence withheld is refused rather than silently redacted. Public
release of retained contents requires separate disclosure authority.
