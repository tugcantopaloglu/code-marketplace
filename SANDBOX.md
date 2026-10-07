# Offline sandbox approval

The sandbox scans completed VSIX files on the incoming share and writes a report
next to each file. `package.vsix`, `package.sigzip`, and `package.sandbox.json`
form one import unit. Finish all three files using temporary names before
publishing the final VSIX name. The marketplace never runs the uploaded extension.
Publisher-restricted imports also require `package.publisher.json` as described
in [PUBLISHERS.md](PUBLISHERS.md).

The intended scanner is Nextron THOR. Its adapter must translate the native
result into this contract and sign it. This repository validates reports; it
does not implement a malware scanner or claim that test reports are real scans.

## Report contract

The report is a JSON envelope with `keyId`, `payload`, and `signature` fields.
`payload` is standard Base64 containing UTF-8 JSON with these exact fields:

```json
{
  "schemaVersion": 1,
  "sha256": "lowercase SHA-256 of the complete original VSIX",
  "status": "completed",
  "verdict": "clean",
  "scanner": "sandbox product or adapter identity",
  "scanId": "unique scan identifier",
  "scannedAt": "2026-10-07T09:00:00Z",
  "expiresAt": "2026-10-08T09:00:00Z"
}
```

`signature` is standard Base64 containing the Ed25519 signature over the UTF-8
bytes of `code-marketplace/sandbox-report/v1\n` followed by the decoded payload
bytes. The newline is one LF byte. No JSON reserialization or canonicalization
is performed during verification. An adapter written in Go can use
`sandbox.Sign` with the scanner's dedicated private key.

Only `status: completed` and `verdict: clean` are accepted. Missing reports,
unknown keys, invalid signatures, duplicate or unknown JSON fields, pending or
non-clean results, hash mismatches, future dates, and expired reports are rejected.
The default maximum report age and validity interval are both 24 hours.

## Trust configuration

Deploy public keys separately from the incoming share:

```json
{
  "keys": {
    "sandbox-2026": "Base64-encoded 32-byte Ed25519 public key"
  }
}
```

The private key stays in the sandbox or its trusted adapter. People who can
upload packages must not be able to modify the trusted public-key configuration,
write the published marketplace storage, or obtain the sandbox's signing key.
Rotate keys by deploying a new public key before switching the scanner key ID.

```console
code-marketplace add ./incoming --extensions-dir ./extensions --require-signature --require-sandbox-report --sandbox-trust ./sandbox-trust.json
```

Setting `--sandbox-trust` also makes the report mandatory. `--sandbox-report`
can select a report for a single local VSIX. HTTP imports cannot use this gate.
The legacy `add` command without sandbox flags remains available to trusted
operators. Production scheduled imports must use the mandatory gated import
command and restrict write access to the importer.

Sandbox approval is independent of the Marketplace `.sigzip` signature. The
importer matches the signature archive to the VSIX; Microsoft VS Code still
performs its own cryptographic extension signature verification.

## THOR deployment

Run THOR on a fixed licensed scanner host with access to the incoming share.
THOR's host-based license is associated with the scanner hostname. Keep the
THOR binary, license, rule updates, and adapter private key on that host; do not
bundle them into the public marketplace image. See the vendor's
[deployment documentation](https://thor-manual.nextron-systems.com/en/latest/usage/deployment.html).

The adapter must bind one completed scan to the exact VSIX bytes, not merely
to a directory-wide result or matching filename. A truncated, aborted, unreadable,
or partially scanned archive must not become `clean`. Enable and validate archive
content scanning for VSIX ZIP files. The native THOR JSON log and the deployed
THOR version are needed before implementing its result mapping. THOR is a
scanner; successful process exit alone is not a clean-file verdict.

## Scheduled import

```console
code-marketplace import --incoming-dir ./incoming --extensions-dir ./published --sandbox-trust ./sandbox-trust.json --publisher-policy ./publisher-policy.json
```

This command always requires both authenticated sandbox approval and a matching
`.sigzip`. It reads the incoming share without modifying or deleting inputs.
JSON results distinguish `imported`, `unchanged`, `waiting`, `rejected`,
`conflict`, and `failed`. Missing sidecars remain `waiting`. Rejections are
expected policy decisions; infrastructure failures and version conflicts cause
a nonzero exit after processing the other files.

Receipts and the original sandbox reports are published atomically alongside
each package, hidden from download endpoints. Matching files are not extracted
again. Existing versions with different package or signature bytes, missing
receipts, or corrupted published files are never overwritten. Approval expires
for new imports; expiration does not revoke an already published package.
Existing packages from the legacy importer require an explicit operator
migration before this importer can adopt them.

The incoming and published directories must be separate. Only the importer
needs write access to published storage. Native file locks prevent concurrent
imports and automatically release when a process exits. Hidden lock files remain
on disk; do not delete them while an importer is running. The storage filesystem
must support shared file locking and atomic renames.
