# Generated fixtures

> **Acronym:** scalable transparent argument of knowledge (STARK).

The real-proof self-test creates fixtures under the ignored `local-artifacts/` directory
instead of committing a reusable private witness or a large proof binary.

Generated positive fixtures:

- `receipt.msgpack` — real composite STARK receipt;
- `public.json` — authenticated journal plus non-authoritative convenience metadata.

Generated negative fixtures:

- `mutated-public.json` — changed public threshold;
- `transplanted-public.json` — changed subject and challenge;
- `corrupted-receipt.msgpack` — corrupted serialized receipt;
- `tampered-journal.msgpack` — decoded journal changed without regenerating the seal.

Additional negative witnesses are generated only in memory: below-threshold,
`Unknown`, and `Conflicted`. The self-test requires every negative case to be rejected
and writes the Boolean results to `self-test-results.json`.

This layout avoids publishing the private witness bytes in a fixture while retaining a
reproducible generator and verifier.
