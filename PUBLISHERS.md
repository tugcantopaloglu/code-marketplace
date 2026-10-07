# Configurable publisher admission

Verified Publisher is the official Marketplace domain verification badge. It is
separate from the Microsoft signature on a VSIX and is not a malware scan.
Sandbox approval and a matching `.sigzip` remain mandatory in every publisher
mode. See the official
[verification documentation](https://code.visualstudio.com/api/working-with-extensions/publishing-extension#verify-a-publisher).

## Policy

`import` defaults to `--publisher-mode verified`:

| Mode | Requirement |
| --- | --- |
| `verified` | Authenticated Marketplace provenance with a verified domain; also apply the allowlist when nonempty. |
| `allowlist` | Authenticated provenance from an allowlisted publisher; the badge is optional. |
| `any` | Explicitly disable publisher restrictions; sandbox and signature checks still apply. |

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

```console
kubectl create configmap marketplace-publisher-policy --from-file=publisher-policy.json=./publisher-policy.json
```

The legacy `add` command remains available to trusted operators and does not
apply this publisher policy. Production schedulers must use `import`; restrict
write access to published storage to that importer.
