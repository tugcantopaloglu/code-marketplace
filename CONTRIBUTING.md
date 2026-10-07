# Contributing

## Development

### Requirements

- Go at the version specified in `go.mod` or later
- GNU Make

### Building from source

Build all platform binaries:

```console
make build
```

Build a specific platform:

```console
make bin/code-marketplace-linux-amd64
```

Available targets:
- `bin/code-marketplace-darwin-amd64`
- `bin/code-marketplace-darwin-arm64`
- `bin/code-marketplace-linux-amd64`
- `bin/code-marketplace-linux-arm64`
- `bin/code-marketplace-windows-amd64`
- `bin/code-marketplace-windows-arm64`

### Running locally

```console
mkdir extensions
go run ./cmd/marketplace/main.go server --extensions-dir ./extensions
```

When you make a change that affects people deploying the marketplace please
update the changelog as part of your PR.

You can use `make gen` to generate a mock `extensions` directory for testing and
`make upload` to upload them to an Artifactory repository.

## Tests

To run the tests:

```
make test
```

To run the Artifactory tests against a real repository instead of a mock:

```
export ARTIFACTORY_URI=myuri
export ARTIFACTORY_REPO=myrepo
export ARTIFACTORY_TOKEN=mytoken
make test
```

See the readme for using the marketplace with code-server.

When testing with code-server you may run into issues with content security
policy if the marketplace runs on a different domain over HTTP; in this case you
will need to disable content security policy in your browser or manually edit
the policy in code-server's source.

## Microsoft VS Code signature integration test

Build the Windows executable, then provide two existing signed VSIX releases
of the same extension:

```powershell
go build -o ./bin/code-marketplace.exe ./cmd/marketplace
./scripts/test-vscode-signature.ps1 -VSIX ./new.vsix -Signature ./new.sigzip -PreviousVSIX ./old.vsix -PreviousSignature ./old.sigzip
```

Omit the previous release parameters to test installation only. Add
`-LegacyEmptySignatures` to confirm that `--sign` preserves an imported real
signature. The test copies the installed Microsoft VS Code into a temporary
directory, configures that copy to use a loopback marketplace, and uses isolated
profiles and extension directories. It does not change the installed editor.

The test imports each local VSIX and `.sigzip` pair through the directory import
command with `--require-signature`. It requires successful signature verification with execution confirmed
in the real VS Code logs. It verifies asset hashes and requires a structurally
valid altered VSIX to fail signature verification. Inputs are local files; the
marketplace does not download anything from the public Marketplace during the
test. The resulting evidence directory contains the editor and server logs.

This tests the VS Code installation backend through its CLI. The Extensions
view's Install button still needs a separate interactive check.

## Releasing

1. Check that the changelog lists all the important changes.
2. Update the changelog with the release date.
3. Push a tag with the new version.
4. Update the resulting draft release with the changelog contents.
5. Publish the draft release.
6. Bump the Helm chart version once the Docker images have published.
