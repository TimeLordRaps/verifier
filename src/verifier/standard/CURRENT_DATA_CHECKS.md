# Current retained dataset checks

Dataset integrity and lineage (DATA); Verifier Standard (VSTD); JavaScript Object
Notation (JSON). This experimental specification registers five bounded native
propositions under `verifier-current-object-obligations-1`. Counts are
dimensionless; payload and certificate bounds count encoded bytes.

The externally selected request binds the exact DATA record, collection, retained
evidence, check, proposition, installed mechanism, policy and limits. The selected
record's payload is the native dataset artifact. Every namespace record reconstructs
exactly and the finite collection passes typed composition. Evidence carries the
retained records. The checker recomputes the selected proposition from those records;
a producer's result is never accepted as a substitute.

| Current coordinate | Native check | Exact proposition |
|---|---|---|
| DATA-1.2 | inventory | Recompute every retained shard's canonical bytes, record count, ordered record commitments and digest-tree root. |
| DATA-1.4 | schema | Inventory plus exact shared or per-shard field names and supported plain value types for every retained record. |
| DATA-2.1 | lineage | Inventory plus exact ordered transformation replay, with all retained shards accounted for and no overwriting or unresolved inputs. |
| DATA-4.1 | splits | Inventory plus complete exclusive membership of the selected final shards and record-identity separation between their declared splits. |
| DATA-4.4 | overlap | Inventory and split checks plus pairwise exact and lexical overlap within the selected nonempty training and evaluation inventories. |

These current registrations explicitly reuse the native operations associated with
the listed legacy spellings in `DOMAIN_OBLIGATIONS.md`. They require new selection
and evidence under the current semantic version. They do not transfer a legacy
verdict, collapse neighboring numbered obligations, or establish their prerequisites
or whole-tier coverage. In particular, inventory does not establish global record
identity uniqueness, source rights, retention completeness outside the selected
records, or the legacy DATA-1.3 proposition. Source shards used for transformation
replay may be outside the separately declared final-shard split boundary.

Schema types are string, integer, number, boolean, array and object. Boolean values
are not integers. Required fields are exact, including rejection of extra columns.
Transformations are concatenation, projection, equality filtering and deduplication
of retained canonical records; unsupported transformations remain UNKNOWN.

Lexical overlap uses lowercased whitespace-token sequences, sets of contiguous
`n`-token tuples for selected integer `n` from 1 through 32, and intersection size
divided by union size. Both sets empty means zero lexical overlap. Exact comparison
uses stripped text with case preserved. Every selected pair must stay at or below
the independently selected ceiling in [0,1); an exact match fails regardless of
that ceiling. This is a defined finite text predicate, not semantic contamination
detection or a claim about material absent from the retained inventory.

`data_checks_request`, `data_checks_policy`, `build_data_checks_certificate` and
`recheck_data_checks_certificate` in `verifier.domains.contracts.data_checks` implement
selection, execution and exact replay. Evidence, request, policy and certificate use
distinct `verifier-current-data-checks-*-1` schema identifiers. Public replay uses
`vstd current-object check` with the exact semantic version, objective, represented
kind DATA, request and policy. The two permanent command aliases use the same route.

Limits select at most 256 objects, 100,000 native operations, 100,000 composition
operations, 4,096 items per input container, four mebibytes each of evidence,
composition payload and reference bytes, and eight mebibytes of certificate bytes.
Native operations include retained input traversal before native evaluation.
Composition and native operation budgets are separate. Namespace records retain
their own one-mebibyte per-object payload limit. These are computational bounds,
not a physical-resource or process-isolation guarantee.

Missing retained evidence, unsupported native semantics and exhausted selected
bounds produce UNKNOWN. Contradictory retained evidence produces FAIL. Malformed
external selection, changed installed dependencies and substituted or forged
certificates are rejected. Rechecking reconstructs the entire certificate exactly,
including its result and retained bytes. Canonical certificates cannot be partially
redacted while retaining their canonical status.

Trust-root labels do not authenticate an observer. External origin, rights,
sampling quality, live acquisition, independent correctness, complete required
objective coverage, public checkability, authority and polished issuance remain
unestablished. Positive and independently rebound negative fixtures are in
`tests/test_current_data_checks.py`; the inventory records these five propositions
without closing any kind or tier.
