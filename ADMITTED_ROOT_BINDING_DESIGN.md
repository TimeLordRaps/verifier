# Admitted trusted-root binding: test-first design

Terminology: identifier (ID); JavaScript Object Notation (JSON); operating system (OS).

Status: REPAIRED OWNER GREEN, PENDING INDEPENDENT SUCCESSOR REVIEW. The original
14-member coordinate was independently rejected: its frozen suite passed
100/100, while a separate adversarial run produced 5 controls PASS and 5
invariants FAIL. The candidate then recorded its own 32 PASS / 6 FAIL repair
RED, implemented the four bounded repairs, and passed 41/41 focused plus
109/109 combined with zero failures, errors, or skips. These are bounded private
synthetic results, not independent acceptance or release readiness.

## Acceptance proposition

For an explicit `RootAdmission` record supplied by an external authority, and a
caller-owned, already-open trusted Windows directory handle, `bind_admitted_root`
returns a binding only if all of the following hold:

1. the admission is an instance of `RootAdmission` and each field is exact
   (`admission_id` nonempty text; `generation`, volume serial and file index are
   nonnegative non-bool integers; the three digests are lowercase 64-hex);
2. `current_generation` and the consumed-admission ledger are supplied (absence
   fails closed);
3. the admission is not stale (`generation == current_generation`) and not
   reused (`admission_id` not already in the caller-owned ledger);
4. the manifest bytes match `manifest_sha256` and the manifest's source
   coordinate equals `source_coordinate` (accepted reader checks);
5. the manifest contains no duplicate JSON object key, every member path is
   Unicode scalar text in Unicode Normalization Form C (NFC), and the members
   contain no exact or portable case-folded path collision (accepted reader
   checks, before any member I/O; path bytes are never normalized or rewritten);
6. `materialization_coordinate` equals the specification digest over the parsed
   members (below);
7. the borrowed root handle is a positive integer, is a disk directory, is not a
   reparse point, and its volume serial and 64-bit file index equal the admitted
   identity (`GetFileInformationByHandle` on the borrowed handle; no path
   access);
8. only then is the admission recorded in the caller-owned ledger.

Afterwards the binding:

- reads only admitted member paths (exact string match; anything else is
  `UNLISTED_MEMBER_REQUEST` before any call into the Windows opener);
- duplicates the caller's numeric root handle for each read, validates the held
  duplicate's disk/directory/reparse status and admitted identity, delegates the
  held duplicate to `exact_windows_anchored_member_reader`, then closes it;
- checks that the bytes returned for path P match P's own declared digest and
  size;
- propagates `MaterializedMemberError` unchanged through both `read_member` and
  `load_scope`, including `unclosed_handles`, and accounts for failure to close
  the per-read root duplicate;
- never closes or takes ownership of the caller's original root handle.

Passing these checks establishes only that the named members' bytes match the
externally admitted declaration under the admitted root identity at bind time.
It does not establish repository completeness, semantic correctness, or release
admissibility. The reader's `completeness == "UNKNOWN"` and
`release_admissible == False` are preserved.

## Materialization coordinate (consistency only)

    materialization_coordinate = sha256(canonical_json({
        "members": sorted-by-path [{"path","role","sha256","size_bytes"}, ...],
        "source_coordinate": <manifest source coordinate>
    }))

canonical_json = `sort_keys=True, separators=(",", ":"), ensure_ascii=True`.

This is a derived consistency check. A matching value does not prove authority;
the admission record remains the only authority input.

## Check order (encoded by the tests)

root handle type → admission type → admission fields → generation presence and
type → ledger presence → stale → reuse → manifest digest/coordinate/collision
(via accepted reader parse) → materialization coordinate → root identity
(disk, directory, not reparse, volume/index) → binding construction → ledger
commit. Each read then performs exact allowlist lookup → DuplicateHandle → held
root disk/directory/reparse/identity validation → anchored read → byte binding →
held-root close accounting.

Handle, admission and manifest refusals occur before any native call, so they
are testable with a synthetic handle integer. Root identity is the first native
call.

## Residual UNKNOWN (not closed by this design)

- The accepted opener does not expose the identity of the object it opened, so
  identity-to-bytes is bounded by the declared digest and size of each member,
  not by file identity. Two members with identical content cannot be told apart
  by bytes alone.
- Volume serial plus 64-bit file index is a 64-bit identity. Filesystems with
  128-bit file IDs (for example ReFS) are UNKNOWN.
- The consumed-admission ledger is caller-owned and process-scoped. It is not
  durable and is not a cross-session replay defense.
- Network filesystems, junctions/mount points beyond the reparse checks, reuse
  of an identity tuple itself, and unsupported filesystem behavior remain
  UNKNOWN. Handle-value substitution between bind and read is bounded by the
  per-read duplicate-then-validate step; live OS handle-value reuse was not
  forced in these tests.

## Failure codes

Binding-level (`AdmittedRootError`, a `ScopeInputError` subclass, so reader-level
handling still applies): `ROOT_HANDLE_INVALID`, `ADMISSION_TYPE_INVALID`,
`ADMISSION_FIELD_INVALID`, `ADMISSION_GENERATION_MISSING`,
`ADMISSION_LEDGER_MISSING`, `ADMISSION_STALE`, `ADMISSION_REUSED`,
`MATERIALIZATION_COORDINATE_MISMATCH`, `ROOT_IDENTITY_MISMATCH`,
`ROOT_IDENTITY_UNAVAILABLE`, `ROOT_NOT_DIRECTORY`, `ROOT_REPARSE_REFUSED`,
`ROOT_NOT_DISK`, `ROOT_DUPLICATE_UNAVAILABLE`,
`ROOT_HANDLE_DUPLICATE_FAILED`, `UNLISTED_MEMBER_REQUEST`, and per-request
member checks
`MEMBER_OBSERVATION_INVALID`, `MEMBER_NOT_REGULAR`, `MEMBER_CONTENT_INVALID`,
`MEMBER_SIZE_MISMATCH`, `MEMBER_DIGEST_MISMATCH`.

Reader-level codes are passed through unchanged (`MANIFEST_DIGEST_MISMATCH`,
`SOURCE_COORDINATE_MISMATCH`, `MEMBER_PATH_COLLISION`, ...). Opener-level
`MaterializedMemberError` codes (`ANCHORED_OPEN_CANCELLED`,
`ANCHORED_READ_CANCELLED`, `MEMBER_CLOSE_FAILED`, ...) and binding-level
`ROOT_HANDLE_CLOSE_FAILED` are passed through unchanged with cleanup metadata.

## Files

- `tests/test_admitted_root_binding.py`: contract tests (new).
- `ADMITTED_ROOT_BINDING_DESIGN.md`: this note (new).
- `scripts/admitted_root_binding.py`: the single new production module. It
  reuses `exact_source_scope._parse_manifest` (private, same repository) so the
  manifest checks are the accepted reader's own.

Unchanged and byte-pinned: `scripts/exact_source_scope.py`,
`scripts/windows_anchored_member.py`, `scripts/exact_materialized_member.py`,
and all existing tests and design documents.
