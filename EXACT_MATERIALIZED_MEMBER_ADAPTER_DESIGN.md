# Exact materialized-member adapter: test-first design

Status: private synthetic-root test-first extension. Production filesystem
capability is unavailable and must fail closed before any file open.

The accepted reader and its frozen tests remain byte-pinned. The adapter will
provide only the reader's exact-member callback. It receives one synthetic root
and one already validated relative path at a time. It has no walk, glob, Git,
network, provider, package or repository-completeness interface.

Member paths are Unicode scalar text in Unicode Normalization Form C (NFC).
The adapter independently rejects invalid or non-NFC text before filesystem
inspection and never normalizes or rewrites path identity.

For each named path it must:

1. inspect the root and each exact parent component with `lstat`;
2. reject links, reparse points and non-directories in parent components;
3. inspect the exact leaf, reject links/reparse points and require a regular file;
4. reject the declared on-disk size before opening when it exceeds the bound;
5. require a reviewed anchored/no-follow opener that does not re-resolve an
   unpinned parent path; refuse with `ANCHORED_OPEN_UNAVAILABLE` before opening
   any file when that capability is absent;
6. compare the anchored handle identity to the pre-open observation;
7. stream bounded bytes, reject early truncation and bound overruns;
8. compare post-read handle metadata and a final exact leaf observation;
9. return only `MemberObservation(kind="REGULAR", content=...)`.

The earlier twelve synthetic controls remain useful but were insufficient: on
Windows, `getattr(os, "O_NOFOLLOW", 0)` evaluated to zero, and a deterministic
parent-substitution model made leaf validation and pathname open agree on an
outside target, which was then read. That RED is retained separately.

The existing controls now inject a private synthetic pathname opener only to
retain their unit coverage. That injection confers no platform or production
capability. The default production boundary refuses before `os.open`; a future
implementation must use reviewed OS-backed root/parent handle traversal and
must receive an independent race-focused review before any copied real-member
run.

The separately reviewed Windows opener is exposed to this adapter only through
`exact_windows_anchored_member_reader(trusted_root_handle=...)`. That entry
point receives a borrowed, already admitted root handle and performs no path
open, `lstat` or discovery. It retains bounded reads, metadata stability checks,
cooperative cancellation before each read, and exact byte/digest checking by
the callback reader. Descriptor-close failure is never treated as cleanup: the
descriptor is reported in `MaterializedMemberError.unclosed_handles`. The
original pathname entry point remains unconditionally
fail-closed. This integration is still a private candidate pending its own
independent acceptance and confers no copied-real-member credit.

The reader continues to establish the exact byte size and digest, but its
callback exposes no identity token for independent auditing. Windows anchored
traversal, junction/mount handling, network filesystems, identity reuse and all
unsupported interleavings remain `UNKNOWN`. No atomic no-replacement, adapter
capability, repository-completeness or release claim is permitted.

