# Release procedure

1. Run the declared conformance tests from a clean checkout. For the integer-layer
   release this includes grounded-certificate, tier, bounded-refusal, depth, Graph,
   schema, emulator/adversarial, provenance-blast-radius, and CLI smoke tests.
2. Build the source release with the internal allowlist builder and verify its SHA-256.
3. Extract that release into a new repository worktree; do not push the internal
   development repository or its history.
4. Set the reproducible-build timestamp before building distributions:

   ```bash
   export SOURCE_DATE_EPOCH=1787270400
   python -m pip wheel --no-cache-dir --no-deps --wheel-dir dist .
   ```

   The release build backend is pinned in `pyproject.toml` to
   `setuptools==84.0.0` and `wheel==0.48.0`.

5. Build twice in clean directories and require identical wheel SHA-256 values.
6. Install the wheel with `--no-deps`, run the stdlib lifecycle smoke, then test each
   optional profile independently.
   Also run `vstd hardware list --json` and the deterministic virtual probe/verification
   lifecycle; never place the test HMAC key in a committed fixture.
7. Require a zero-match boundary scan for private project names, local or home-directory
   paths, credentials, and personal email addresses.
8. Create the GitHub tag and release only after the public tree, hashes, version, and
   claim boundaries match. Existing release tags remain untouched.
9. Let Zenodo archive the GitHub release, then record the issued DOI additively.
10. Configure PyPI Trusted Publishing against the exact repository and workflow. Require
   manual approval on the production `pypi` environment.

Do not reuse a wheel built without the fixed `SOURCE_DATE_EPOCH`; ordinary wheel ZIP
metadata can otherwise differ across builds even when the source is identical.
