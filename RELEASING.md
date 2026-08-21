# Release procedure

1. Run the declared conformance tests from a clean checkout.
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
7. Create the GitHub tag and release only after the public tree, hashes, version, and
   claim boundaries match.
8. Let Zenodo archive the GitHub release, then record the issued DOI additively.
9. Configure PyPI Trusted Publishing against the exact repository and workflow. Require
   manual approval on the production `pypi` environment.

Do not reuse a wheel built without the fixed `SOURCE_DATE_EPOCH`; ordinary wheel ZIP
metadata can otherwise differ across builds even when the source is identical.
