# Windows anchored member opener: pre-edit contract

Status: private, synthetic-fixture, test-first dependency candidate under
HARNESS-AGNOSTIC AGENT CONSTITUTION v2. The accepted production adapter remains
fail-closed at `ANCHORED_OPEN_UNAVAILABLE` while this candidate is unaccepted.

## Locally available interface

The existing 64-bit Windows Python runtime exposes, without installation:

- `ntdll!NtCreateFile` and `ntdll!RtlNtStatusToDosError`;
- `kernel32!DuplicateHandle`, `CloseHandle`,
  `GetFileInformationByHandleEx`, `GetFileType` and `GetCurrentProcess`;
- `msvcrt.open_osfhandle` for transferring a final Windows handle into the
  existing bounded `os.fstat`/`os.read`/`os.close` path.

No pathname fallback is permitted. Absence or ABI rejection of any required
interface produces `ANCHORED_OPEN_UNAVAILABLE` before a member is opened.

## Trust and ownership

The caller supplies a trusted, already-open directory handle for the selected
materialized root. This module does not derive that root handle from a path and
does not claim that the root's original acquisition was safe.

For one member-open operation:

1. the caller retains ownership of the supplied root handle;
2. after an initial cancellation check, the opener duplicates it and owns only
   the duplicate;
3. the duplicate must identify a disk directory and must not carry the reparse
   attribute;
4. every child handle returned by `NtCreateFile` becomes opener-owned;
5. an old parent handle is closed only after the child has been opened and
   validated, so traversal is always relative to a held directory object;
6. a final regular-file handle transfers to a C-runtime descriptor only after
   validation; successful `open_osfhandle` transfers ownership to that
   descriptor and the caller of the opener owns the descriptor;
7. every cancellation and failure path makes exactly one close attempt for every
   opener-owned handle. A conversion failure closes the still-owned final
   Windows handle. A failed close is never silently treated as cleanup: the
   exact handle is retained in `AnchoredOpenError.unclosed_handles` and the
   result is not admissible.

The trusted root handle must remain valid until duplication completes. Closing
or maliciously reusing the caller's handle concurrently is outside this
contract and must be treated as `UNKNOWN`, not accepted behavior.

## Component traversal and refusal

Member text is independently required to be a nonempty tuple of canonical
single components: no empty, dot, dot-dot, slash, backslash, colon or NUL. Each
component must be Unicode scalar text in Unicode Normalization Form C (NFC),
encode as strict UTF-16LE, and contain no more than 255 UTF-16 code units. The
opener rejects rather than normalizes non-NFC text. `UNICODE_STRING.Length` is
derived from the encoded bytes, never Python character count, so non-BMP
characters cannot truncate native selection.

Each component is passed alone as an `UNICODE_STRING` to `NtCreateFile`, with
`OBJECT_ATTRIBUTES.RootDirectory` set to the currently held parent handle.
The native object lookup retains Windows case-insensitive behavior while the
selected-source parser rejects two portable case-fold aliases in one manifest;
spaces are literal component text and are never shell-quoted or split.
Every open uses `FILE_OPEN_REPARSE_POINT`; parent components additionally use
`FILE_DIRECTORY_FILE`, and the leaf uses `FILE_NON_DIRECTORY_FILE`. The opener
never joins an absolute or root-relative pathname.

After every native open and before a child is used as a parent or converted to a
descriptor, `GetFileInformationByHandleEx(FileAttributeTagInfo)` must succeed.
Any `FILE_ATTRIBUTE_REPARSE_POINT` is rejected and closed. Parents must be disk
directories. The leaf must be a non-directory disk object.

Opening a reparse object itself for inspection is not opening its target and
confers no permission to read it. A backend that cannot provide the required
no-follow behavior is unavailable; it must not fall back to `os.open`.

## Cancellation and cleanup

A supplied cancellation predicate is checked before root duplication, before
each component open, immediately after each component open, and immediately
before final handle-to-descriptor transfer. Cancellation raises
`ANCHORED_OPEN_CANCELLED` and closes all owned handles.

This cooperative contract does not claim that it can interrupt a native call
already blocked inside the kernel. `CancelSynchronousIo` being exported does
not by itself establish safe in-flight cancellation; that remains `UNKNOWN` and
is outside the initial capability.

## Pre-edit counterexamples and controls

Frozen tests must first fail at `WINDOWS_ANCHORED_OPENER_MISSING`, then cover:

1. exact component-by-component relative traversal and no pathname fallback;
2. parent replacement after its handle is acquired cannot redirect the next
   lookup because the returned parent handle is the next `RootDirectory`;
3. a reparse root, parent or leaf is rejected before child traversal or final
   descriptor transfer;
4. cancellation before duplication performs no native operation;
5. cancellation after a child open closes the child and all retained parents;
6. native-open, attribute-query and descriptor-conversion failures close every
   owned handle exactly once;
7. malformed components fail before native operations;
8. a final handle is transferred once and not also closed as a Windows handle;
9. an actual synthetic regular file can be opened through the native backend
   and read through the returned descriptor;
10. the existing default adapter remains fail-closed throughout review.

Passing these bounded tests is not evidence that the caller's source root is
trustworthy, that in-flight native cancellation works, that all filesystems or
reparse mechanisms are qualified, or that copied real members may be adopted.
Repository/full-regression/semantic/release status remains `UNKNOWN`/false.
