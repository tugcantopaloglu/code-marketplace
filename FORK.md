# Fork information

This repository is an independently maintained fork of
[coder/code-marketplace](https://github.com/coder/code-marketplace).
The original project was developed by Coder and its contributors.

The original copyright notices and GNU AGPL-3.0 license are preserved.
The initial upstream revision is
`ab77d0e2649ba44f00da0110e098bb97b8a6921f`. Fork modifications began on
2026-10-07. This fork is not an official Coder release.

This repository starts with a single initial commit containing the upstream code
and the fork modifications. The inherited upstream commits and tags are not
included in its Git history.

## Initial changes

- Import detached signature archives with `add --signature`.
- Validate archive structure and match the VSIX size and SHA-256 digest.
- Store and serve signature assets without changing the original VSIX bytes.
- Keep imported signatures when the legacy empty-signature option is enabled.
- Publish release images to this repository's GHCR namespace.
- Remove the workflow that requests signatures for Coder's contributor agreement.

## Push to your repository

Create an empty public repository named `code-marketplace`, then run:

```console
git remote add origin https://github.com/<owner>/code-marketplace.git
git push -u origin main
```

To track upstream changes later, add the original repository separately:

```console
git remote add upstream https://github.com/coder/code-marketplace.git
```

The Go module path remains `github.com/coder/code-marketplace` so existing
internal imports continue to build. It does not determine the Git push
destination. Change the module path and internal imports together if a separate
public Go module identity is required later.

## Build and deploy the fork

```console
go build -o ./bin/code-marketplace ./cmd/marketplace
```

Release workflows use this repository's release assets and publish to
`ghcr.io/<owner>/code-marketplace`. Before deploying with Helm, set
`image.repository` and `image.tag` to the fork image and release you built.
The inherited chart defaults still point to the upstream image.

```console
VERSION=<version> IMAGE_REPOSITORY=ghcr.io/<owner>/code-marketplace docker buildx bake
```

Keep `LICENSE` and the original copyright notices. When deploying a modified
service, prominently offer its network users free access to the corresponding
source for the running revision, including build scripts. A public repository
with an accessible link to that revision can provide the source; present the
offer to marketplace users through your deployment's landing page or onboarding
page. Extension redistribution permissions must be assessed under each
extension's own license.
