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
   python scripts/release_artifacts.py build \
     --ref FULL_PUBLIC_COMMIT_SHA --release 1.0.1 --output-dir dist/candidate
   ```

   The builder uses `git archive`, records exact Git-blob bytes, builds the wheel twice
   from separate source extractions with `SOURCE_DATE_EPOCH` set to the commit timestamp,
   and fails unless the wheels are byte-identical.

4. Install the candidate wheel with `--no-deps`. Run the generic receipt lifecycle,
   `vstd hardware list --json`, and the deterministic virtual probe/verification
   lifecycle. Test each optional dependency profile independently; never place a test
   HMAC key in a committed fixture.
5. Require a zero-match boundary scan of the candidate source archive and wheel for
   private project names, proprietary model identifiers, local or home-directory paths,
   credentials, and personal email addresses.
6. Create the release tag locally at the exact tested commit. Prefer a cryptographically
   signed annotated tag when the maintainer's signing key is available. Rebuild using the
   tag coordinate and compare the new artifacts with the candidate:

   ```bash
   git tag -s v1.0.1 FULL_PUBLIC_COMMIT_SHA
   python scripts/release_artifacts.py build \
     --ref refs/tags/v1.0.1 --release 1.0.1 --output-dir dist/tagged
   ```

   If signing is unavailable, stop and record that the tag itself is unsigned; do not
   describe a GitHub-verified commit or build attestation as a signed tag.
7. Run the verifier independently before upload:

   ```bash
   python scripts/release_artifacts.py verify \
     dist/tagged/verifiable-standard-1.0.1.manifest.json
   ```

   The manifest's source ref MUST resolve to its recorded public commit. The source ZIP
   file set and every member byte MUST match that commit. CRLF/LF equivalence is not
   accepted as byte identity.
8. Push the tag only after all preceding checks pass. Publish exactly the tested source
   ZIP, wheel, and external release manifest. Existing tags and release assets remain
   untouched; corrections are additive.
9. If build provenance attestations are enabled, bind them to the exact uploaded asset
   digests. An attestation complements but does not replace the release manifest or tag
   signature.
10. Let Zenodo archive the GitHub release, then record the issued DOI additively.
11. Configure PyPI Trusted Publishing against the exact repository and workflow. Require
    manual approval on the production `pypi` environment.
