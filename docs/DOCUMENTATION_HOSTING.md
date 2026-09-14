# Documentation hosting

The documentation portal targets `https://verifier-standard.com/`. The corporate
site is `https://vstd-labs.com/`. Hosting configuration is an operational state;
the existence of this guide does not establish that either site is deployed.

## Build and inspect

Build from the public repository using the
[repository walkthrough](REPOSITORY_WALKTHROUGH.md). The portal generator records
both the current source coordinate and the commit behind release tag `v1.3.0`.
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

## Prepare Cloudflare Pages

Use a dedicated Pages project named `verifier-standard-docs`, separate from the
corporate deployment. Upload the **contents** of the portal build directory so
`index.html` is at the deployment root. All required assets are local to the
build. The `_headers` file adds browser security response headers.

Validate the preview before changing the domain: homepage, search, mobile
navigation, released reference, source reference, guide links, and schema routes.
Record `portal-coordinate.json` and the archive digest with the deployment receipt.

## Cut over the domain

The domain previously served a permanent corporate redirect. After the
documentation preview is working, disable that specific redirect, bind
`verifier-standard.com` through Pages Custom domains, and inspect the exact
existing domain-name-system records before replacing a conflicting web record.
Do not purge the zone or modify mail records as part of a documentation cutover.

Check the certificate, apex response, deep documentation paths, search index, and
version links from the public domain. Browsers may retain the previous permanent
redirect; test with a fresh request as well as an existing browser session.
If cutover fails, restore the previous web record and redirect configuration
using the pre-change snapshot, leaving the preview available for diagnosis.

## Preserve published identifiers

Existing schema identifiers remain under
`https://timelordraps.github.io/verifier/schemas/`. Do not rewrite those identifiers
to the new domain, or retire that serving route, as a branding change. The portal
also includes schema files byte-for-byte; this does not assign them new identities.

Keep the current package's documentation metadata unchanged until the new domain
is publicly reachable and validated. Update that metadata in a later authorized
release change, rather than promising an unavailable documentation endpoint.

Publishing the public repository, uploading a build, and cutting over a domain
are distinct operations. Follow the maintainer's authorization for each one.
