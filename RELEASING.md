# Release procedure

Public releases are built only from a commit already present in the public repository.
The release manifest is published beside the source ZIP rather than tracked inside the
source tree. This avoids a self-referential commit field and lets the manifest bind an
exact, publicly resolvable commit.

1. Merge the versioned release change through the public pull-request workflow. Require
   every protected conformance check on the exact candidate commit.
2. From a clean checkout of that commit, run:

   ```bash
   python -m pytest -q
   python -m compileall -q src
   ```

3. Build a pre-tag candidate from the full commit SHA, not a working directory:

   ```bash
   VERSION=1.1.2
   python scripts/release_artifacts.py build \
     --ref FULL_PUBLIC_COMMIT_SHA --release "$VERSION" --output-dir dist/candidate
   ```

   The builder uses `git archive`, records exact Git-blob bytes, and builds both the
   wheel and standard source distribution twice from separate source extractions with
   `SOURCE_DATE_EPOCH` set to the commit timestamp. Setuptools sdist tar and gzip metadata
   are normalized to that timestamp, zero ownership, stable modes, and sorted members.
   The build fails unless each pair is byte-identical and both distributions declare
   `verifier-standard`, version `1.1.2`, import package `verifier`, and the frozen three
   console scripts.

4. Run `twine check` on the candidate wheel and source distribution. Install the
   candidate wheel with `--no-deps`. Run the generic receipt lifecycle,
   `vstd hardware list --json`, and the deterministic virtual probe/verification
   lifecycle. Test each optional dependency profile independently; never place a test
   HMAC key in a committed fixture.
5. Require a zero-match boundary scan of the candidate source archive, wheel, and source
   distribution for
   private project names, proprietary model identifiers, local or home-directory paths,
   credentials, and personal email addresses.
6. Create the release tag locally at the exact tested commit. Prefer a cryptographically
   signed annotated tag when the maintainer's signing key is registered and available.
   Rebuild using the tag coordinate. The source ZIP, wheel, and source distribution MUST
   be byte-identical to the commit-coordinate candidate. The external manifest MUST
   differ only where its `source.ref` changes from the full commit SHA to the tag ref,
   plus the manifest's own resulting digest:

   ```bash
   VERSION=1.1.2
   git tag -s "v$VERSION" FULL_PUBLIC_COMMIT_SHA
   python scripts/release_artifacts.py build \
     --ref "refs/tags/v$VERSION" --release "$VERSION" --output-dir dist/tagged
   ```

   If tag signing is unavailable, an unsigned annotated tag is permitted only through
   `.github/workflows/release.yml`. That workflow records `UNSIGNED` in the release
   notes and MUST create GitHub/Sigstore artifact attestations for the source ZIP,
   wheel, source distribution, and external manifest. An artifact attestation is not
   described as a tag signature.
7. Run the verifier independently before upload:

   ```bash
   VERSION=1.1.2
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
11. Confirm that `https://pypi.org/project/verifier-standard/1.1.2/` lists the same wheel
    and source-distribution SHA-256 values as the GitHub release and external manifest.
    PyPI ownership establishes control of the distribution coordinate only; it does not
    establish adoption, consensus, certification, or exclusive control of the Python
    import name `verifier`.
