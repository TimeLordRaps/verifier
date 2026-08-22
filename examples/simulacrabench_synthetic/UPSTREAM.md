# Upstream provenance and license

The source snapshot in this example is copied from:

- Repository: <https://github.com/SituatedEvals/public>
- Commit: [`1bb2d46026fe0d91979448c3d916506be0608513`](https://github.com/SituatedEvals/public/commit/1bb2d46026fe0d91979448c3d916506be0608513)
- License: MIT, reproduced byte-for-byte at [`source_snapshot/LICENSE`](source_snapshot/LICENSE)

`public_packet.json` records the SHA-256 digest, byte length, pinned source URL, and local
snapshot path for every copied file. `verify_packet.py` refuses any mismatch.

The copied files are:

- `README.md`
- `LICENSE`
- `config.yml`
- `data/sample.json`
- `make_sandbox.py`
- `score.py`
- `baseline/marginal_counts/main.py`
- `baseline/marginal_counts/requirements.txt`
- `tools/check_submission_zip.py`

The VSTD packet, crosswalk, verifier, and challenge demonstration are original to this
repository. The snapshot is included to make the public, verdict-critical source bytes
self-contained rather than treating a remote digest as availability.
