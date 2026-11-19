# Offline internal VSIX releases

Use this workflow for extensions your organization builds and distributes through
its own catalog. The importer verifies a release signature and a clean sandbox
report for the exact original VSIX bytes. It adds VS Code's `PrivateMarketplace`
property to the catalog metadata and serves the VSIX unchanged. These packages use
`.internal.json` and `.sandbox.json` sidecars. Marketplace packages continue to
use the configured Marketplace publisher and signature checks.

## Configure the importer once

On the trusted release workstation, generate a release key scoped to the exact
extension IDs from the packages' manifests. Use a protected, empty directory
outside the incoming share. Replace the example IDs with your actual IDs.

```powershell
.\code-marketplace.exe internal keygen company.extension-one company.extension-two --key-id internal-release-1 --output-dir C:\Protected\MarketplaceRelease
```

Keep `internal-private.pem` on the workstation. Transfer only
`internal-policy.json` to the Kubernetes administrator. Each key in this file
authorizes only its listed `publisher.extension` IDs. Those IDs are reserved for
this workflow, so choose IDs that do not overlap with mirrored extensions.
Multiple keys may authorize the same ID for rotation.

```bash
kubectl -n code-marketplace create configmap marketplace-internal-policy --from-file=internal-policy.json=./internal-policy.json --dry-run=client -o yaml | kubectl -n code-marketplace apply -f -
```

Add the following to your existing Helm overrides. The separate sandbox ConfigMap
must already contain the trusted scanner public key. Internal packages require
sandbox approval even when the importer uses `sandboxMode: disabled` for
Marketplace packages.

```yaml
importer:
  internalPolicy:
    configMap: marketplace-internal-policy
  sandboxTrust:
    configMap: marketplace-sandbox-trust
    key: sandbox-trust.json
```

For an existing manually managed CronJob, update the server and importer images to
the new version. Mount both ConfigMaps read-only and add
`--internal-policy /internal-policy/policy.json` and
`--sandbox-trust /sandbox-trust/trust.json` to the importer arguments, using the
actual mounted filenames. Preserve the existing incoming and published PVCs and
the Marketplace publisher settings.

See [SANDBOX.md](SANDBOX.md) for the sandbox adapter and signed report format.
The test report generator is for isolated tests.

## Publish a new package or update

1. Build the final `.vsix`. For updates, keep the same publisher and extension
   name and increment the version in the extension source before building.
2. On the release workstation, sign the final VSIX. Repeat for each package.

   ```powershell
   .\code-marketplace.exe internal sign .\company.extension-one-1.0.0.vsix --key-id internal-release-1 --signing-key C:\Protected\MarketplaceRelease\internal-private.pem
   ```

3. Obtain the matching, signed `.sandbox.json` from the trusted scanner. Place
   `.internal.json` and `.sandbox.json` in `incoming` with the same basename as
   the VSIX, then finish copying the VSIX under a temporary `.part` name and
   rename it to `.vsix`. If the scanner watches for final `.vsix` files on that
   share, publish the release report first and let the importer wait for the
   scanner's report.
4. Check that the importer reports `imported` or `unchanged`. If processed
   archiving is enabled, the three files move together. A previously published
   version with different bytes returns `conflict`.
5. In the VS Code instance already connected to the internal catalog, search for
   the extension ID and install it. Windows VS Code 1.146.0 supports installation
   and updates from this catalog with signature verification enabled.

The release report is valid for 24 hours by default. Use `--valid-for` to select
up to 168 hours. To renew an expired report, produce a fresh copy in a different
directory with `--output-dir` and replace the old report on the incoming share.
An expired release or scan report blocks new imports until it is renewed.

## Drop an internal VSIX into incoming

Version `v4` adds optional automatic release signing on Linux. Once configured,
use a trusted release account to upload
`incoming/internal-plusaicode-0.1.23.vsix`. Use a `.part` filename during the
copy, remove group and other write permissions, and rename to `.vsix` when the
copy is complete. The importer checks the Linux file owner and extension ID,
waits for the scanner's matching `internal-plusaicode-0.1.23.sandbox.json`,
then creates `internal-plusaicode-0.1.23.internal.json` and publishes the package.
The scanner must watch the same incoming share and sign real scan results.

On the file server, assign a dedicated non-root upload identity. The Linux node
must see its numeric UID on the file. Use a share configuration that preserves
distinct identities and prevents other uploaders from assuming this UID or
writing files it owns. Check a representative upload with
`stat -c 'uid=%u mode=%a' incoming/internal-plusaicode-0.1.23.vsix`.
The importer rejects group-writable or world-writable packages for automatic
signing. Use the manual release signature workflow if the share maps uploaders
to one identity.

Generate a dedicated automatic release key once. Preserve existing entries in
`internal-policy.json` when adding this key. Scope it to the extensions that the
upload identity may release.

```powershell
.\code-marketplace.exe internal keygen tusas.tusascode --key-id tusas-auto-1 --output-dir C:\Protected\MarketplaceAuto
```

Apply the public policy as described above, and store the matching private key in
a Kubernetes Secret accessible only to the importer workload and its operators.
Run this from a protected operator environment with access to the key:

```bash
kubectl -n code-marketplace create secret generic marketplace-internal-auto-sign \
  --from-file=internal-private.pem=./internal-private.pem
```

For Helm, include these settings alongside the internal and sandbox ConfigMaps.
Replace the example UID with the trusted uploader's numeric UID:

```yaml
importer:
  internalAutoSign:
    secretName: marketplace-internal-auto-sign
    keyId: tusas-auto-1
    uploaderUid: "12001"
```

For a manually managed CronJob, mount the Secret read-only at
`/internal-auto-sign`, allow the importer to write to `/incoming`, and append:

```yaml
- --internal-auto-sign-key
- /internal-auto-sign/internal-private.pem
- --internal-auto-sign-key-id
- tusas-auto-1
- --internal-uploader-uid
- "12001"
```

By default, a verified scan is required before the importer creates the release
sidecar. If a sidecar already exists, the importer verifies it. Archive mode
moves the generated sidecar together with the package after publication.

### Operate without a scanner for trusted internal uploads

In v5, set `importer.internalAutoSign.skipSandbox: true` in Helm or add
`--internal-auto-skip-sandbox` to the manual CronJob arguments. This setting
requires the automatic signing key, internal policy, and trusted uploader UID.
Only allowed extensions uploaded as `internal-*.vsix` by that Linux UID can be
imported under this setting, including retries with an existing release sidecar.
The importer records `sandboxMode: disabled` and generates the release sidecar.

In a cluster whose Marketplace importer already uses `sandboxMode: disabled`,
you may omit the sandbox trust ConfigMap and mount. All other internal packages
still require a signed sandbox report and wait if sandbox trust is unavailable.
