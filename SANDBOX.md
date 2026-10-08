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

## Temporary operation without sandbox approval

Sandbox admission defaults to `required`. Explicitly select `disabled` while the
scanner integration is being prepared:

```console
code-marketplace import --incoming-dir ./incoming --extensions-dir ./published --sandbox-mode disabled --publisher-policy ./publisher-policy.json
```

Omit `--sandbox-trust` in this mode. No sandbox trust ConfigMap, scanner key, or
`.sandbox.json` is needed. Verified Publisher provenance, the configured publisher
allowlist, matching original `.sigzip`, package validation, immutable versions,
and file locking continue to apply. This mode does not perform a malware scan.
Receipts and per-file results record `sandboxMode: disabled` without inventing
a clean verdict or writing a sandbox report. Management displays that status.

For Helm, set `importer.sandboxMode: disabled`; the chart omits the sandbox volume
and trust arguments. The default remains `required`. For manual CronJobs, pass
`--sandbox-mode disabled` and remove the sandbox volume and its mount. The image
must support this flag. An existing image with mandatory sandbox admission cannot
be changed into this mode by removing its trust argument alone.

To enable scanning later, restore `required` and deploy real scanner public keys
and authenticated reports. Previously published packages stay available. When
the same bytes are reimported with genuine clean approval, the importer adds
the sandbox record without replacing the VSIX or signature. Missing reports
still wait; malicious or invalid reports never upgrade an existing receipt.

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

Prepare a dedicated signing key on the trusted scanner adapter host with Node.js:

```console
node scripts/create-sandbox-key.cjs ./sandbox-keys thor-2026
```

This creates `sandbox-private.pem` and public `sandbox-trust.json`. The future
THOR adapter uses this private key and `keyId: thor-2026` to sign authenticated
scan results. Key generation does not perform a scan or create a clean verdict.
Keep this key separate from the collector key. Only the public JSON leaves the
adapter host. The adapter itself still needs a native THOR report and version
before its result mapping can be implemented.

On an offline cluster operator host, keep public configuration files in a
protected directory outside the incoming share. For the manual deployment, the
ConfigMap data keys and mounts are:

| Local file | ConfigMap in `code-marketplace` | Importer mount |
| --- | --- | --- |
| `sandbox-trust.json` | `marketplace-sandbox-trust` | `/sandbox-trust/sandbox-trust.json` |
| `publisher-policy.json` | `marketplace-publisher-policy` | `/publisher-policy/publisher-policy.json` |

Merge trusted keys into existing files when rotating or adding hosts; preserve
the publisher allowlist. To create or update these two ConfigMaps:

```bash
set -o pipefail
kubectl -n code-marketplace create configmap marketplace-sandbox-trust --from-file=sandbox-trust.json=./sandbox-trust.json --dry-run=client -o yaml | kubectl -n code-marketplace apply -f -
kubectl -n code-marketplace create configmap marketplace-publisher-policy --from-file=publisher-policy.json=./publisher-policy.json --dry-run=client -o yaml | kubectl -n code-marketplace apply -f -
```

Never store a private key in these ConfigMaps. The scheduler uses the current
mounted public files; no image rebuild is required. Missing ConfigMaps prevent
the pod from mounting its volumes. Invalid public-key values fail importer
startup. Valid trust with a missing `.sandbox.json` leaves that package `waiting`.

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

This command defaults to authenticated sandbox approval and always requires a
matching `.sigzip`. It reads the incoming share without modifying or deleting inputs.
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

## Archiving and incoming reports

Both features are optional; the default still leaves input files untouched:

```console
code-marketplace import --incoming-dir ./incoming --extensions-dir ./published --sandbox-mode disabled --publisher-policy ./publisher-policy.json --processed-dir ./processed --write-incoming-report
```

Only `imported` and `unchanged` packages are archived. Their VSIX, signature,
publisher provenance, and sandbox report when present stay together in a unique
`processed/<VSIX SHA-256>-<UUID>` directory. Waiting, rejected, conflicted, and
failed inputs remain available for correction. Reports include `archiveStatus`,
`archivedTo`, `archiveError`, and `recoveryDir` where applicable.

Originals are held in a private `.archive-<UUID>` directory while verified copies
are written under `processed/.partial-<UUID>`. The copy uses the hashes captured
during admission. An atomic directory rename commits the bundle before originals
are removed. This supports distinct Kubernetes subPath mounts without requiring
a rename between mounts. Changed inputs or failed copies restore the originals
without overwriting newly uploaded files. Copies or held originals are preserved
if recovery cannot finish. `.archive-state.json` records the files, hashes,
publication result, and destination. An unfinished holding directory is reported
as `recoveryDirs` on subsequent runs and requires operator review.

`incoming/import-report.json` is replaced atomically at startup, after each
package, and at completion. It contains timestamps, `running`, `completed`, or
`failed` run status, a top-level error, and per-file decisions. Startup policy
load failures are recorded when the incoming path is writable. A second importer
cannot overwrite the active importer's report while the published-storage lock
is held. The protected `.last-import.json` also remains available to management.
The next run replaces the latest report; each archived bundle retains its journal.

With these features enabled the importer needs incoming write access and a
separate writable processed directory. Pre-create a processed subPath before
starting a Kubernetes Job. Keep publisher policy and scanner trust outside the
share. Reporting and archiving do not change signature or publisher enforcement
or the selected sandbox mode. A pod that cannot mount its volumes has not started
the application and cannot write a report; diagnose that failure in pod Events.
