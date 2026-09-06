# Stored interoperability components

Verifier Standard (VSTD) version 1.3.0 introduces an **experimental stored component
format**, `VSTD-COMPONENT-PACKAGE-1`. It is a local, self-contained JavaScript Object
Notation (JSON) document, not a receipt, installation archive, or conformance result.
It retains component descriptions and exact artifact bytes so a catalog can be shared,
inspected and used for verification-surface-hole planning without executing its contents.
The [stored-document schema](../standard/schemas/vstd-component-package-1.schema.json)
describes its structural contract; runtime checks additionally enforce byte digests,
canonical catalog form and reference bindings.

## What travels together

A package contains an identifier and version; unsigned publisher, license and description
declarations; an exact catalog schema 1.1 registry; retained artifacts encoded as base64;
implementation bindings from every component to retained artifact paths; and explicitly
declared dependencies. Each artifact has a portable relative path, media type, bytes and
Secure Hash Algorithm 256-bit (SHA-256) digest. Paths are logical names, not extraction
destinations. Implementation references are opaque descriptive coordinates; the
first-party seed uses module/symbol strings, but the container is not Python-specific.

The registry distinguishes solver, prover, checker, verifier, adapter, translator and
other roles. It retains native result vocabulary and claim boundaries. Planning schemas
and native accepted schemas remain separate. Sharing a schema, family label or domain
tag never supplies a missing mechanism match.

The strict loader rejects malformed structures, unsupported schema identifiers, duplicate
identifiers, broken bindings, invalid paths and content-digest mismatches. It does not
extract files, follow artifact paths, import implementations, resolve dependencies, fetch
external content or execute components. Default bounds are 256 artifacts, 16 mebibytes of
decoded artifact content and 32 mebibytes for the encoded document; one mebibyte is
1,048,576 bytes. Oversized input is rejected, not treated as an incomplete successful
package. Every stored registry array is bounded to 256 entries and text to 4096
characters, with control characters and unpaired Unicode surrogates rejected. Catalog
scalar fields that permit empty text retain that meaning.

The local loader accepts ordinary non-link files only, checks the opened file identity,
and uses nonblocking/no-follow opening where the operating system provides it. Pipes,
devices, links and Windows reparse files are rejected. These checks do not promise a
wall-clock bound on filesystem access or protection against privileged concurrent
filesystem mutation; they are not an execution sandbox.

## Canonical content identity

Canonical package bytes use Unicode Transformation Format, 8-bit (UTF-8). Characters
outside the American Standard Code for Information Interchange (ASCII) character set are
escaped. Object keys are sorted; separators are
compact commas and colons without extra whitespace; no trailing newline is added. Artifact
records sort by path, implementation records by component identifier, dependency records
by dependency identifier, and reference arrays lexicographically. The embedded registry
must already have catalog 1.1's canonical descriptor and array form; importing a stored
package does not migrate or silently normalize an older or noncanonical catalog. No field
accepts floating-point values, and non-finite numbers are rejected.

Artifact digests cover decoded artifact bytes. The registry digest covers its canonical
JSON bytes. The package digest covers the whole canonical package, including content and
declarations. Each digest is 64 lowercase hexadecimal characters. An optional expected
package digest compares canonical content, not transport-file whitespace or object-key
order; formatting the file differently does not change its content identity.

## Create, retain, inspect and plan

The experimental Python application programming interface (API) is available through
`verifier.interoperability.storage` and the `verifier.interoperability` facade:

```python
from verifier.interoperability import load_component_package, save_component_package

package = load_component_package("reference-components.json", expected_digest=trusted_digest)
report = package.inspect()
registry = package.registry
save_component_package(package, "retained-reference-components.json")
```

Here `trusted_digest` must come from a separately trusted source. Saving requires an absent
destination; it does not overwrite an existing file. The constructor types are
`PackageArtifact`, `ImplementationBinding`, `PackageDependency` and
`StoredComponentPackage`. `canonical_json_bytes()` retains a deterministic representation;
`canonical_digest()` identifies those package bytes. A load/save round trip preserves
artifact bytes, even when they are not text.

The command-line interface (CLI) can inspect a stored package and supply its registry to
the existing nonexecuting planner:

```bash
vstd components inspect reference-components.json --json --expected-sha256 EXPECTED_DIGEST
vstd surface analyze geometry.json --plan --package reference-components.json --expected-package-sha256 EXPECTED_DIGEST --json
```

`EXPECTED_DIGEST` is the expected 64-character hexadecimal package digest, not a literal
value. Omitting the expected digest checks internal consistency but does not establish
which externally intended package was supplied. The planner still requires exact matches
for declared holes, retains blocked and unmatched candidates, and grants no authority to
execute. See the [working reference-snapshot example](../examples/stored_components/README.md).

Package-selected plans bind the validated canonical package digest inside the plan,
not merely in the enclosing catalog report. The experimental Python call is
`plan_validation(analysis, package.registry, package=package)`. Plans and readiness
reports expose `binding_scope` (`STORED_PACKAGE` or `REGISTRY_ONLY`) and
`package_digest`; registry-only planning does not imply implementation-byte binding.

Call `assess_execution_readiness(..., package=package)` with the exact package when
checking a package-selected plan. Missing package bytes leave readiness
`NOT_ESTABLISHED`; substitution is `INVALID`. A package-bound caller-supplied
`AUTHORIZED` declaration must name `plan_digest`, the SHA-256 hexadecimal digest of
`plan.canonical_json_bytes()`. Changing retained implementation bytes changes the
plan and invalidates reuse of that declaration. These are declaration-consistency
checks, not authentication of the caller or a grant of execution permission.

## Boundaries that survive storage

- Retained bytes and digest consistency do not establish correctness, safe execution,
  authentic publisher identity, an independently valid license grant or native availability.
- A package digest does not authenticate itself. Publisher and license fields are unsigned
  declarations. Artifact binding is not evidence that the claimed entrypoint has the
  described behavior.
- Dependency declarations may refer to retained artifacts or describe unresolved external
  prerequisites. They are not an installation lockfile, resolver or proof of complete
  executable dependency closure. Missing qualification remains `NOT_ESTABLISHED`.
- Portable storage on Linux, Windows and macOS is separate from qualification of a native
  verifier on those platforms. No native support claim follows from successful parsing.
- Imported catalog membership and declared availability remain descriptive. A readiness
  report still checks supplied declarations only; it does not perform execution or
  post-execution reassessment.
- Version 1.3.0 includes the storage and consumption foundation. A future Cloudflare site
  may serve and index these files; this change deploys no site and provides no hosted
  execution or publisher accounts.

The stored format is experimental under the [API stability policy](API_STABILITY.md).
Readers dispatch on its exact identifier and the exact embedded catalog version. An
incompatible future layout requires a distinct format identifier and explicit migration;
readers must not reinterpret unknown formats as this one. This does not change any frozen
receipt identifier or grant a new numbered-profile result.
