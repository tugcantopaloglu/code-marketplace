# Configurable publisher admission

Verified Publisher is the official Marketplace domain verification badge. It is
separate from the Microsoft signature on a VSIX and is not a malware scan.
A matching `.sigzip` remains mandatory in every publisher mode. Sandbox approval
is required by default and can be explicitly disabled temporarily in the importer.
See [SANDBOX.md](SANDBOX.md) and the official
[verification documentation](https://code.visualstudio.com/api/working-with-extensions/publishing-extension#verify-a-publisher).

## Policy

`import` defaults to `--publisher-mode verified`:

| Mode | Requirement |
| --- | --- |
| `verified` | Authenticated Marketplace provenance with a verified domain; also apply the allowlist when nonempty. |
| `allowlist` | Authenticated provenance from an allowlisted publisher; the badge is optional. |
| `any` | Explicitly disable publisher restrictions; signature and configured sandbox checks still apply. |

Unknown modes fail. Missing provenance waits. Forged signatures, expired
observations, mismatched identities or hashes, and ineligible publishers are
rejected. The default maximum provenance age and validity interval are seven
days, configurable with `--publisher-max-age`.

Keep the public collector keys and allowlist outside the incoming share:

```json
{
  "keys": {"collector-2026": "Base64-encoded 32-byte Ed25519 public key"},
  "allowedPublishers": ["ms-vscode", "ms-python"]
}
```

An empty allowlist permits all verified publishers in `verified` mode. Use actual
publisher names, not display names such as `Microsoft`, prefixes, or wildcards.
For a stable Marketplace publisher GUID, use an entry such as
`id:5f5636e7-69ed-4afe-b5d6-8d231fb3d3ee`. Entries match exact names or exact
GUIDs. `allowlist` mode requires at least one entry. Policy changes apply on the
next import without rebuilding the application.

```console
code-marketplace import --incoming-dir ./incoming --extensions-dir ./published --sandbox-trust ./sandbox-trust.json --publisher-policy ./publisher-policy.json
```

## Connected collection, offline admission

Create a dedicated collector key using Node.js on a trusted connected host:

```console
node scripts/create-collector-key.cjs ./collector-keys collector-2026
code-marketplace collect --extension ms-vscode.notepadplusplus-keybindings --key-id collector-2026 --signing-key ./collector-keys/collector-private.pem --output-dir ./collected
```

Keep `collector-private.pem` on that host with restricted filesystem permissions.
Deploy only `publisher-policy.json` to the importer. Use separate collector and
sandbox keys. Neither private key belongs on the share or in the marketplace
image. The importer trusts your collector's observation; Microsoft does not sign
the publisher JSON itself.

Collection queries the official Marketplace over HTTPS, downloads the exact
VSIX and signature, verifies their identity and archive hash match, and signs
their hashes with the publisher GUID, name, domain, `isDomainVerified`, version,
platform, and observation times. The cluster verifies this record offline.
The output directory must be empty; `.part` files are published with the VSIX
last. The default selection is the latest compatible stable version. Use
`--target-platform win32-x64`, `--version` for an exact release, or `--pre-release`
to include preview versions when selecting the latest package.

Transfer `.vsix`, `.sigzip`, and `.publisher.json` together. The sandbox then adds
the matching `.sandbox.json`. All sidecars use the VSIX basename. An arbitrary
VSIX cannot prove its publisher by its manifest name alone; the provenance must
match both its original bytes and its signature archive.

## Batch collection

Select extensions in [collectors/extensions.example.yaml](collectors/extensions.example.yaml):

```yaml
targetPlatform: win32-x64
publisherMode: verified
allowedPublishers: []
extensions:
  - id: ms-vscode.notepadplusplus-keybindings
    version: 1.0.7
  - id: ms-python.python
  - id: golang.Go
    targetPlatform: linux-x64
```

Run on the trusted internet-connected collector. Reuse its existing key and key
ID; creating a new key for every batch requires updating importer trust each time.
The cluster can keep its existing image; only the connected collector needs a
binary with `collect-batch` support.

```console
code-marketplace collect-batch --config ./extensions.yaml --output-dir ./collected-20261008 --key-id collector-2026 --signing-key ./collector-keys/collector-private.pem --valid-for 168h
```

The output directory must be empty. Downloads run sequentially with three attempts
per extension; `--attempts` accepts 1 to 5. An error does not stop the remaining
selections. Failed batches return a nonzero exit status and preserve successful
packages. `batch-report.json` records every selection, result, resolved version,
platform, hashes, and provenance expiry. Review it before transfer. Identical
universal packages selected for several platforms share one bundle and have a
`reused` result. A different package with the same filename is rejected.

The flat `incoming` output contains matching `.vsix`, `.sigzip`, and
`.publisher.json` files. Transfer only those files to the offline incoming share,
with sidecars first and each VSIX staged as `.part` before renaming it last.
Keep the batch report, private key, and publisher policy outside the share.
The collector does not produce `.sandbox.json`; authenticated clean scan reports
are required when sandbox mode is `required`. The default seven-day provenance window applies
to every package separately. Import before expiry or collect fresh provenance.

`publisherMode` defaults to `verified` and accepts the same three modes as the
importer. `allowedPublishers` accepts exact publisher names or `id:GUID` entries.
The collector filters the output; the offline importer still enforces its own
policy. An omitted version selects the latest stable package. Set `preRelease:
true` on an entry to include previews. A per-entry `targetPlatform` overrides the
global platform. Platform selection refers to the editor, not the collector host.
Dependencies and extension-pack members must also be listed when needed offline.

To start a YAML list from extensions installed in an internet-connected VS Code:

```bash
printf 'targetPlatform: win32-x64\npublisherMode: verified\nextensions:\n' > extensions.yaml
code --list-extensions | sed 's/^/  - id: /' >> extensions.yaml
```

Review the generated selection. This export selects the latest stable releases;
set `version` explicitly where a pinned release is required. For a failed batch,
create a selection with its failed entries and collect into a new empty directory.

## Publisher report

The envelope uses `keyId`, Base64 `payload`, and Base64 Ed25519 `signature`, as in
sandbox reports. The signing context is `code-marketplace/publisher-report/v1\n`
followed by the exact payload bytes. Distinct signing contexts prevent reuse of
a sandbox signature as publisher provenance. The payload is:

```json
{
  "schemaVersion": 1,
  "source": "https://marketplace.visualstudio.com",
  "publisher": {
    "id": "Marketplace publisher GUID",
    "name": "ms-vscode",
    "displayName": "Microsoft",
    "domain": "https://microsoft.com",
    "isDomainVerified": true
  },
  "extension": "notepadplusplus-keybindings",
  "version": {"version": "1.0.7"},
  "sha256": "SHA-256 of the original VSIX",
  "signatureSha256": "SHA-256 of its sigzip",
  "observedAt": "2026-10-07T10:00:00Z",
  "expiresAt": "2026-10-08T10:00:00Z"
}
```

Platform-specific records add `targetPlatform` inside `version`. Approval and
the signed report are private stored metadata. Expiry limits new imports; policy
changes do not automatically remove already published packages. Review the
existing catalog when tightening policy. Existing versions without publisher
receipts require explicit operator migration before gated reimport.

## Kubernetes

Configure `importer.publisherPolicy.mode`, `maxAge`, `configMap`, and `key` in
Helm. `verified` is the default; its policy ConfigMap is mandatory when enabling
the importer. The offline example uses `marketplace-publisher-policy`.
`any` mode does not require this extra ConfigMap. Policy is mounted read-only
and importer egress remains blocked.

To manage trusted public keys and allowed publishers directly in values YAML,
leave `configMap` empty and configure `trustedKeys` plus `allowedPublishers`.
Helm creates the policy ConfigMap from those fields. Management uses the same
policy, mode, and age. See [MANAGEMENT.md](MANAGEMENT.md).

```console
kubectl create configmap marketplace-publisher-policy --from-file=publisher-policy.json=./publisher-policy.json
```

The legacy `add` command remains available to trusted operators and does not
apply this publisher policy. Production schedulers must use `import`; restrict
write access to published storage to that importer.
