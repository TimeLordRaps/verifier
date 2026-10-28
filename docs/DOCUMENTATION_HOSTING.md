# Documentation hosting

The public documentation is assembled by the GitHub Pages workflow from the
qualified `main` commit. The documentation domain is
`https://verifier-standard.com/`; the corporate site is `https://vstd-labs.com/`.
Publishing a source branch does not update either public site.

On 2026-09-27, public responses from the GitHub Pages address and the documentation
domain both reported documentation version `1.5.0` and source commit
`fc2a20c68d01920eda7e4e1bf14dfbcb334a7634`. The domain response carried
Cloudflare headers. These observations establish the served coordinates at that
time, not the account-side routing rule or future propagation. The separate
Cloudflare Pages preview at `verifier-standard-docs.pages.dev` still reported a
`1.3.0` documentation build and is not a current-release source.

## Build and inspect

Build from the public repository using the
[repository walkthrough](REPOSITORY_WALKTHROUGH.md). GitHub Pages uses
`scripts/build_pages.py` and records its exact source in
`documentation-coordinate.json` and the deployment manifest. The separate portal
generator records both the current source coordinate and the commit behind release
tag `v1.5.0`.
Release documentation is built from that tag in a separate process. Equivalence
between the tag and the published distribution remains a release-process
dependency; the portal build does not silently claim to establish it.

The repository checks fetch this pinned release for documentation tests and
retain a `documentation-portal-<commit>` preview artifact alongside the existing
Pages preview. This prepares a reviewable build on each proposed source change;
it does not automatically deploy to Cloudflare or alter domain records.

The generated search index stays with the site. Search queries stay in the
browser. Code-copy buttons use the browser clipboard only when clicked.
The color theme preference is stored locally when browser storage is available.

## Check the domain after GitHub Pages promotion

First confirm the GitHub Pages address serves the
expected `main` source commit and documentation version. Then check the same
coordinate, homepage, a deep guide,
reference page, and browser certificate at `verifier-standard.com`. A matching coordinate
is a routing check, not proof that every page is byte-identical or that the
Cloudflare account configuration was inspected. Investigate any mismatch in the
existing authenticated Edge session before changing routing.

If an intentional routing change is needed, inspect the exact Cloudflare web
records and rules, save their previous state, and validate a preview before
cutover. Leave mail records and unrelated redirects untouched. Verify the
public route again after the change; restore the saved web configuration if it
fails. A stale Pages preview must not be promoted as the current documentation.

## Preserve published identifiers

Existing schema identifiers remain under
`https://timelordraps.github.io/verifier/schemas/`. Do not rewrite those identifiers
to the new domain, or retire that serving route, as a branding change. The portal
also includes schema files byte-for-byte; this does not assign them new identities.

Keep the current package's documentation metadata unchanged until the new domain
is publicly reachable and validated. Update that metadata in a later authorized
release change, rather than promising an unavailable documentation endpoint.

Publishing the public repository, promoting GitHub Pages, and changing a domain
route are distinct operations. Follow the maintainer's authorization for each one.
