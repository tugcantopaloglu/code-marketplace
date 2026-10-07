# Active Directory management

Start the separate management process using YAML:

```console
code-marketplace admin --config config/admin.example.yaml
```

The public UI is `/admin/`. This listener provides no public VS Code gallery or
download endpoints. The normal `server` process remains separate and mounts
published storage read-only. Management requires existing, separate published,
incoming, and audit directories. Relative paths resolve against the YAML file.
Unknown keys, duplicate keys, multiple documents, and YAML aliases fail startup.

## Authentication and authorization

Use `ldaps://dc.example:636` or `ldap://dc.example:389`. The latter always upgrades
with StartTLS before any bind; there is no plaintext bind or certificate bypass.
Server certificates must match the configured hostname and a trusted CA.
`ldap.caFile` adds the organization's CA to the trust pool. Keep the bind password
in `ldap.bindPasswordFile`, preferably a mounted Kubernetes Secret. Passwords and
session tokens are never written to the audit log or returned by configuration APIs.

The service account searches for exactly one enabled AD person under
`ldap.userBaseDN`, using the fixed `sAMAccountName` or `userPrincipalName` attribute.
User input is escaped for LDAP filters. The user's own DN/password is then bound
to verify the password. Read-only service-account searches evaluate authorized AD
groups using Microsoft's transitive membership matching rule. Nested groups are
supported; primary-group membership alone is not sufficient. Configure dedicated
security groups and give the service account only the required read permissions.

`readerGroups` permits catalog, import results, and publisher policy access.
`adminGroups` also permits uploads and version revocations, with admin taking
precedence when both roles match. No configured group means no access. Sessions
recheck AD at most every minute and before every administrative mutation. AD
failure or removed membership invalidates the session. Password changes alone do
not immediately invalidate sessions; absolute lifetime and idle timeout still apply.

The browser gets a random opaque `__Host-marketplace-admin` cookie with Secure,
HttpOnly, Path `/`, and SameSite Strict. Session records are held in memory, expire
after configurable absolute/idle limits, and disappear on restart. Helm runs one
admin replica with Recreate strategy. Logout removes the server-side session.
Mutations require the configured HTTPS Origin and a session CSRF header. Login
requires that same Origin and JSON. The service has no CORS allowance, uses a CSP
without inline/external scripts, and limits login attempts, active sessions,
concurrent directory requests, and concurrent uploads.

Terminate HTTPS at a trusted ingress and route only that ingress to the admin
listener. `publicURL` is an exact origin, such as `https://marketplace-admin.internal`;
it must match the externally visible host. Forwarded headers never grant identity
or alter the accepted Origin. Audit remote addresses refer to the actual TCP peer,
usually the ingress; retain ingress logs for client IP correlation. Login IP limits
apply to that peer, plus a separate per-account limit. Configure proxy body limits
and timeouts for permitted upload sizes. No proxy-specific annotations are assumed.

## Upload and revoke

Uploads accept multipart fields `vsix`, `signature`, `publisherReport`, and the
optional `sandboxReport`. VSIX and signature are required; publisher provenance is
required in verified/allowlist mode. The maximum VSIX size is 512 MiB, signature
34 MiB, each report 64 KiB. Filenames supplied by clients are ignored. The server
validates package identity, archive limits, signature/hash correspondence, and
current authenticated publisher policy. A sandbox sidecar is accepted as opaque
input and must pass the scheduled importer's independent authenticated scan gate.
The management service never creates a clean scan report or directly publishes an
uploaded extension. Microsoft VS Code performs the signature certificate check.

Uploads stage privately on the incoming volume, sync files, and publish sidecars
before the final VSIX filename. Existing basenames are not overwritten. Scanners
and importers must ignore hidden staging directories and only process completed
top-level VSIX files. A failed final rename may leave sidecars for operator cleanup.
The scanner then creates the matching authenticated report. CronJob results are
persisted as private `.last-import.json` and shown in the UI. The last run can
replace earlier results, so retain scheduler logs for historical import decisions.

Revoking a version requires a reason. A private revocation marker blocks future
gated imports of that exact publisher/name/version/platform, including changed
bytes. The package is moved into a private `.revocation-*.package` directory on the
same volume and disappears from downloads. Other versions/platforms are unaffected.
Cached gallery listings may take `server.listCacheDuration` to update; downloads
stop immediately. Revocation and scheduled imports share a native lock. Packages
already installed on clients are not remotely uninstalled.

Markers and archived packages remain for operator review and backup. A failed move
can leave a marker with the package still present; the UI reports a failure and
audit intent remains. Inspect storage before retrying. There is no web restore or
permanent-delete endpoint. To restore, an authorized operator must explicitly review
the archived package and its approvals, remove the marker, and reimport through the
normal gates. The trusted legacy `add` CLI can bypass revocation/admission gates;
restrict published-volume write access to importer, admin, and trusted operators.

Audit JSON lines record authentication, authorization revocation, reads, and mutation
intent/result in `auditFile`. Intent is synced before a mutation; unavailable audit
storage blocks it. If the result write fails after a completed mutation, the API
reports that partial outcome. Use a dedicated persistent audit volume, external log
retention/rotation, and protected backups. Audit records are not cryptographically
tamper-proof against administrators with write access to that volume.

## YAML and Kubernetes

Apply `helm/values-offline.yaml` together with `helm/values-admin.yaml`, replacing
the internal hosts, AD DNs, CA, CIDR, PVC names, and image tag. The admin component
is disabled by default. The chart generates its config YAML; passwords stay in
`admin.bindSecret`, and the AD CA comes from `admin.caConfigMap`. Create these from
local files without putting passwords in shell arguments or values files:

```console
kubectl create secret generic marketplace-ad-bind --from-file=password=./ad-bind-password.txt
kubectl create configmap marketplace-ad-ca --from-file=ldap-ca.pem=./organization-ca.pem
```

Create the admin TLS Secret separately with the certificate trusted by clients.
Its NetworkPolicy permits only the selected ingress peers, configured AD CIDRs and
LDAP port, and DNS in the configured DNS namespace. Marketplace and importer keep
their own offline policies. The chart always creates the admin policy even when
the general marketplace NetworkPolicy is disabled. The cluster CNI must enforce
NetworkPolicy for these restrictions to take effect.

Publisher mode and age come from `importer.publisherPolicy`, shared with management.
An external `configMap` remains supported. Alternatively leave `configMap` empty
and configure the trusted collector public keys and allowlist entirely in values YAML:

```yaml
importer:
  publisherPolicy:
    mode: verified
    configMap: ""
    trustedKeys:
      collector-2026: Base64-encoded-Ed25519-public-key
    allowedPublishers:
      - ms-vscode
      - ms-python
    maxAge: 168h
```

The chart generates the trusted JSON ConfigMap from this YAML. Do not configure
both an external ConfigMap and inline keys. Never place private signing keys in
values, uploads, or container images. UI policy edits are intentionally absent;
YAML remains the configuration source. Helm changes restart admin for configuration
updates and change future CronJobs. Mounted credential/public-policy changes are
read on subsequent operations after Kubernetes propagates the volume update; a CA
change requires an admin restart. Tightening admission does not revoke old packages.

Published and incoming PVCs are shared between admin and other components. Use
storage with shared file locks and atomic same-volume rename. RWX supports pods on
different nodes; RWO requires compatible node placement. Audit must be a separate
PVC. UID/GID 10001 needs write access to incoming/published/audit; regular server
has read-only published storage, and importer has read-only incoming storage.

Local tests exercise the real LDAP client over a synthetic LDAPS/StartTLS server,
untrusted certificates, nested-group filters, group revalidation, expired sessions,
CSRF/Origin, reader restrictions, publisher-bound uploads, revocations, and audit
failure. Real organization AD and deployed ingress/storage verification remains
necessary when those environment values become available.
