# Release procedure

> **Acronyms:** carriage return and line feed (CRLF); digital object identifier (DOI);
> hash-based message authentication code (HMAC); line feed (LF); Secure Hash Algorithm 256-bit (SHA-256);
> Coordinated Universal Time (UTC); ZIP archive format (ZIP).

Public releases are built only from a commit already present in the public repository.
The release manifest is published beside the source ZIP rather than tracked inside the
source tree. This avoids a self-referential commit field and lets the manifest bind an
exact, publicly resolvable commit.

Development branches may record precise contradictions with [`TIME.md`](TIME.md) set to
`Status: OPEN`; normal pull-request checks do not prohibit that state. Publication is
different: the tag-triggered workflow runs `python scripts/check_time_status.py` against
the exact tagged checkout and fails unless it contains exactly one `Status: CLEAR` line.
There is no subjective override.

The source version may be prepared as 1.2.0 while the release does not exist. During that
period, `CHANGELOG.md` says `UNRELEASED`, `CITATION.cff` identifies a release candidate and
has no `date-released`, and install instructions distinguish a source checkout from the
latest published package. Before tagging, land an explicit release-finalization change that
uses the actual publication date consistently in the changelog and citation metadata; do
not fabricate or backdate it. The tag workflow enforces this with
`python scripts/check_release_metadata.py --version <version>` and also refuses
release-candidate Zenodo metadata.

1. Merge the versioned release change through the public pull-request workflow. Require
   every protected conformance check on the exact candidate commit.
2. From a clean checkout of that commit, run:

   ```bash
   python -m pytest -q
   python -m compileall -q src
   ```

3. Build a pre-tag candidate from the full commit SHA, not a working directory:

   ```bash
   VERSION=1.2.0
   python scripts/release_artifacts.py build \
     --ref FULL_PUBLIC_COMMIT_SHA --release "$VERSION" --output-dir dist/candidate
   ```

   The builder uses `git archive`, records exact Git-blob member bytes, and rewrites the
   source ZIP with a UTC commit timestamp, stable Unix modes, sorted members, and stored
   compression. It builds both the wheel and standard source distribution twice from
   separate source extractions with `SOURCE_DATE_EPOCH` set to the commit timestamp.
   Generated packaging text is normalized to LF; wheel `RECORD` is rebuilt after
   normalization; ZIP metadata, tar metadata, gzip metadata, ownership, modes, and member
   order are canonical. The build fails unless each pair is byte-identical and both
   distributions declare `verifier-standard`, version `1.2.0`, import package `verifier`,
   and the frozen three console scripts.

   The protected conformance gate separately builds this complete artifact set on
   Windows and Linux and compares every byte. Do not prepare a tag unless that
   cross-platform comparison passed on the exact candidate commit.

4. Run `twine check` on the candidate wheel and source distribution. Install the
   candidate wheel with `--no-deps`. Run the generic receipt lifecycle,
   `vstd hardware list --json`, and the deterministic virtual probe/verification
   lifecycle. Test each optional dependency profile independently; never place a test
   HMAC key in a committed fixture.
5. Require a zero-match boundary scan of the candidate source archive, wheel, and source
   distribution for
   private project names, proprietary model identifiers, local or home-directory paths,
   credentials, and personal email addresses.
6. Confirm `python scripts/check_time_status.py` passes, release-candidate metadata has
   been finalized with the actual intended publication date, and then create the release
   tag locally at the exact tested commit. Prefer a cryptographically
   signed annotated tag when the maintainer's signing key is registered and available.
   Rebuild using the tag coordinate. The source ZIP, wheel, and source distribution MUST
   be byte-identical to the commit-coordinate candidate. The external manifest MUST
   differ only where its `source.ref` changes from the full commit SHA to the tag ref,
   plus the manifest's own resulting digest:

   ```bash
   VERSION=1.2.0
   git tag -s "v$VERSION" FULL_PUBLIC_COMMIT_SHA
   python scripts/release_artifacts.py build \
     --ref "refs/tags/v$VERSION" --release "$VERSION" --output-dir dist/tagged
   ```

   If tag signing is unavailable, an unsigned annotated tag is permitted only through
   `.github/workflows/release.yml`. That workflow records the GitHub tag-object
   verification result and reason in the release notes and MUST create GitHub/Sigstore
   artifact attestations for the source ZIP, wheel, source distribution, and external
   manifest. An artifact attestation is not described as a tag signature.
7. Run the verifier independently before upload:

   ```bash
   VERSION=1.2.0
   python scripts/release_artifacts.py verify \
     "dist/tagged/verifier-standard-$VERSION.manifest.json"
   ```

   The manifest's source ref MUST resolve to its recorded public commit. The source ZIP
   file set and every member byte MUST match that commit. CRLF/LF equivalence is not
   accepted as byte identity.
8. Push the tag only after all preceding checks pass. The tag-triggered release workflow
   rechecks protected-main ancestry, package version, the successful `conformance-gate`,
   the full test suite, deterministic build, installed wheel, and artifact manifest.
   It then attests and publishes exactly the tested source ZIP, wheel, source
   distribution, and external release manifest to the GitHub release. A second job can
   access only the wheel and source distribution, requires approval in the protected
   `pypi` environment, and publishes them through the configured PyPI Trusted Publisher.
   Existing tags and release assets remain untouched; corrections are additive.
9. Verify each downloaded asset with both the external manifest and:

   ```bash
   gh attestation verify PATH_TO_ASSET --repo TimeLordRaps/verifier
   ```

   An attestation complements but does not replace the release manifest, and it does not
   turn an unsigned tag into a signed tag.
10. Let Zenodo archive the GitHub release, then record the issued DOI additively.
11. Confirm that `https://pypi.org/project/verifier-standard/1.2.0/` lists the same wheel
    and source-distribution SHA-256 values as the GitHub release and external manifest.
    PyPI ownership establishes control of the distribution coordinate only; it does not
    establish adoption, consensus, certification, or exclusive control of the Python
    import name `verifier`.
