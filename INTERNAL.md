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
`v3`. Mount both ConfigMaps read-only and add
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
