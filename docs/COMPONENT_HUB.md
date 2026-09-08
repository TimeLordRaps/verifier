# Component hub

Verifier Standard (VSTD) publishes a generated, static view of its experimental stored
component index at [`components/`](https://timelordraps.github.io/verifier/components/).
The hub is a discovery and exact-byte
distribution surface. It is not a package manager, executable registry, trust authority,
ranking service, or conformance result.

The first public index contains one first-party reference package generated from the exact
source checkout used to build the site. Its package version appends the first 12 hexadecimal
characters of that commit to the base release, for example
`1.3.0+git.adc0415ea653`. This label helps readers orient themselves; the canonical package
digest, not the label or locator, identifies the stored content.

## Static files and identity

The generated surface contains:

```text
components/
  index.html
  index.json
  index.sha256
  deployment-coordinate.json
  packages/sha256/<package-digest>.json
```

`index.json` is canonical JavaScript Object Notation (JSON). Each indexed package binds its
relative content-addressed path, canonical package digest, and embedded registry digest.
`index.sha256` records the Secure Hash Algorithm 256-bit (SHA-256) digest of the exact
`index.json` bytes. `deployment-coordinate.json` separately binds that index digest to the
site's source commit and public base uniform resource locator (URL), so the identity-bearing
index can retain host-neutral relative package paths.

The digest sidecar and deployment coordinate do not authenticate themselves. Select an
expected index or package digest through a separately trusted release, commit, signed
statement, or other explicit continuity mechanism when whole-site substitution matters.
Changing a locator without checking the expected digest does not preserve identity.

## Inspect and search locally

Download or otherwise obtain the index and packages through a channel appropriate to your
threat model, then inspect the local files:

```bash
vstd components index inspect components/index.json --json
vstd components index inspect components/index.json \
  --expected-sha256 EXPECTED_INDEX_DIGEST --json
```

Search requires an exact planning schema and interaction mode plus at least one exact
relation or mechanism coordinate:

```bash
vstd components index search components/index.json \
  --schema-id VSTD-2 \
  --interaction-mode STATIC \
  --mechanism-id mechanism:vstd4-grounded-certificate-check \
  --json
```

Search is case-sensitive exact descriptor matching. It does not fetch a package, choose a
preferred implementation, rank results, resolve a latest version, install dependencies,
import code, execute a component, or validate a native result. No match returns
`NO_DECLARED_MATCH_IN_THIS_INDEX`; it does not establish that no matching component exists
outside this bounded index. Indexed availability remains `NOT_CHECKED`, native qualification
remains `NOT_ESTABLISHED`, and ecosystem completeness remains `UNKNOWN` unless separate
mechanisms establish stronger propositions.

## What the generated page may claim

The page may report that exact index and package bytes were generated, parsed, and
digest-checked from one source coordinate. Descriptor fields remain declarations. In
particular, publication or membership does not establish:

- publisher identity, authorship, endorsement, popularity, or license validity;
- native platform support, dependency closure, installation safety, or runtime availability;
- component correctness, claim coverage, interoperability, independent implementation, or
  VSTD conformance;
- authority to execute or to act on a result.

The initial surface accepts no uploads and creates no publisher accounts. Future submission,
authentication, moderation, revocation, transparency, and multi-publisher policies require
their own governed mechanisms rather than being inferred from static hosting.

## Hosting boundary

The generated files use relative package paths and require no server-side function, database,
credential, or secret. They can be served by GitHub Pages or another ordinary static host.
The current documentation and schema canonical URLs remain under
`https://timelordraps.github.io/verifier/`; mirroring those files elsewhere does not silently
move their canonical identity. A future Cloudflare-hosted hub may serve the same generated
index bytes under a separately declared deployment coordinate without changing what those
bytes establish.
