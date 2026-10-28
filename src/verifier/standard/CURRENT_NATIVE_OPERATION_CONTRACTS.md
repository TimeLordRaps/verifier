# Native replay operation metadata

Verifier Standard (VSTD); application programming interface (API); JavaScript
Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256). This distinct
metadata interface describes existing finite native certificate replay. Metadata
availability does not establish successful replay or execution qualification.

`verifier.runtime.native_operation_contracts` exposes three read-only operations:

- `native_replay_operation_catalog(semantic_version=...)` enumerates one exact
  installed registry. The default historical family retains its 408 routes; the
  explicitly selected ten-tier family contains `VERIFIER-6.1` and `VERIFIER-10.1`. These are finite replay predicates; enumeration supplies no whole-tier admission.
  Generic represented-kind rules stay generic. Enumeration is not an exhaustive
  mandatory-obligation census and does not load each operation's support files.
- `lookup_native_replay_operation(semantic_version=..., objective=...,
  represented_kind=..., expected_descriptor_digest=None,
  expected_mechanism_digest=None, expected_source_bindings=None, cancelled=False)`
  describes one exact externally selected registered replay function. There is no
  submitted import path, function, callback, certificate or operation body.
- `export_native_operation_schema(schema_version)` returns canonical bytes of
  one actual packaged schema: `verifier-native-replay-operation-descriptor-1` or
  `verifier-native-replay-operation-lookup-1`. These schemas validate this module's
  descriptor and lookup result only. They are not native witness schemas.

The descriptor's version is `verifier-native-replay-operation-descriptor-1`.
Its operation identifier hashes the canonical exact semantic version, objective
and represented kind; operation version `1` and category
`finite_native_certificate_replay` describe the metadata interface. The two
semantic families remain separate. Historical coordinates are never converted
to the ten-tier hierarchy. No simulation, inference or training execution
operation, Corrigibility coordinate, native constructor or foreign provider is
registered here.

The descriptor retains the selected route's actual proposition, scope and
certificate wire identifier, owner-declared wire identifiers when present, live
Python native and wrapper signatures, and the wrapper's actual enforced
certificate, selection-text, node, depth, integer and container bounds. Selection
text and node allowances apply separately to request and policy capture. Native
owners may enforce tighter policy-selected or additional limits; those remain
`UNKNOWN`. Type annotations and wire identifiers are metadata, not schemas.

The binding records the actual registered replay function's source segment
digest, owner module and function, installed owner mechanism identifier and
mechanism digest, and exact-byte pins for nine package files: owner replay source,
route registry, this module, this specification, certificate, namespace and
receipt helpers, and both exported schemas. The native mechanism digest is
obtained from the registered owner's existing digest function, with the selected
kind argument only for subject-security routes. It binds that owner's declared
source dependencies; lookup never calls its replay function. Raw package-file
pins and hashes of canonical exported schema bytes are deliberately distinct.
Schema bytes used by a descriptor come from the same captured package-file reads.

Lookup `PASS` means only that supported installed metadata was described and any
selected external pins matched. It is not certificate truth or runtime admission.
`metadata_status=AVAILABLE` always coexists with native replay `NOT_RUN`, runtime
availability and full execution `UNKNOWN`. Native request, policy, evidence,
result and error schemas are `UNSUPPORTED`. Effects, disclosures, idempotency,
cancellation and budget qualification are `UNSUPPORTED`; complete mandatory
obligation census remains `UNKNOWN`. Whole-tier conformance, authority and
production admission are `NOT_ESTABLISHED`. An external pin selects bytes; it
does not authenticate their authority or make their operation valid.

Known wrong semantic families, coordinates, represented kinds, malformed pins
and non-plain values raise `NativeOperationRefusal` before support-file reads.
A complete external source-pin map must match the nine selected package names;
known map or digest substitution returns `FAIL` immediately. Cancellation or
outage cannot erase that completed refutation. Missing support bytes, unavailable
owner digest, an actual `MemoryError`, unsupported source/signature metadata or actual cooperative
`asyncio.CancelledError` leave `UNKNOWN` and `metadata_status=UNAVAILABLE`; there
is no source fallback. `cancelled=True` refuses further metadata preparation.
Schema export raises `NativeOperationUnavailable` when its actual packaged schema
cannot be read or does not match the supported closed metadata contract.

Exact primitive captures reject foreign subclasses/conversions, cycles,
nonfinite numbers and excess depth, counts, text or integer size. Reads use chunks
of at most 8192 bytes and are bounded to eight mebibytes per source or 256 kibibytes per schema;
descriptor output is bounded to two mebibytes. These bounds do not qualify native
replay budgets or the owner's dependency-reader implementation. Source snapshots
and annotations do not prove that loaded code and installed files stayed atomic
through concurrent external edits; actual execution qualification remains open.

The command-line interface exposes the same metadata through `vstd operations
catalog`, `vstd operations lookup --semantic-version ... --objective ...
--represented-kind ...`, and `vstd operations schema <schema-version>`.
Outputs are JSON; exit codes are 0 for available metadata, 1 for a known
selector or pin refusal, and 2 for unavailable metadata. Lookup accepts
`--expected-descriptor-digest` and `--expected-mechanism-digest`. These
commands execute no certificate replay. The same commands are available
through the permanent `verifier` and `verifiable` aliases.

Source and installed-package qualification, complete runtime contracts and
any later native witness-schema registration require their own exact-byte
evidence. This module grants no complete application or release conformance.
