# Active Directory management

Start the separate management process using YAML:

```console
code-marketplace admin --config config/admin.example.yaml
```

The public UI is `/admin/`. This listener provides no public VS Code gallery or
download endpoints. The normal `server` process remains separate and mounts
published storage read-only. Management requires existing, separate published
and audit directories. Relative paths resolve against the YAML file.
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

`readerGroups` and `adminGroups` both permit read-only catalog, import results,
and publisher policy access. Admin group membership does not enable data changes.
No configured group means no access. Sessions recheck AD at most every minute. AD
failure or removed membership invalidates the session. Password changes alone do
not immediately invalidate sessions; absolute lifetime and idle timeout still apply.

The browser gets a random opaque `__Host-marketplace-admin` cookie with Secure,
HttpOnly, Path `/`, and SameSite Strict. Session records are held in memory, expire
after configurable absolute/idle limits, and disappear on restart. Helm runs one
admin replica with Recreate strategy. Logout removes the server-side session.
Logout requires the configured HTTPS Origin and a session CSRF header. Login
requires that same Origin and JSON. The service has no CORS allowance, uses a CSP
without inline/external scripts, and limits login attempts, active sessions,
and concurrent directory requests.

Terminate HTTPS at a trusted ingress and route only that ingress to the admin
listener. `publicURL` is an exact origin, such as `https://marketplace-admin.internal`;
it must match the externally visible host. Forwarded headers never grant identity
or alter the accepted Origin. Audit remote addresses refer to the actual TCP peer,
usually the ingress; retain ingress logs for client IP correlation. Login IP limits
apply to that peer, plus a separate per-account limit. No proxy-specific
annotations are assumed.

## Read-only operation

The Graphite Mono interface shows the catalog, admission policy, and latest import
results. It uses local monospace fonts, graphite surfaces, and monochrome tables;
no external fonts or UI assets are fetched. Search and refresh only read metadata.

Upload and version-revocation endpoints are removed, including for members of
adminGroups. There is no YAML flag that enables those endpoints. New extensions
continue to arrive through the existing share/scanner/importer workflow. The UI
cannot change policies or published packages. Previously stored revocation markers
continue to block the relevant versions in the importer.

CronJob results are persisted as private .last-import.json and shown in the import
view. The last run replaces earlier results, so retain scheduler logs for history.
Audit JSON lines record authentication, session revocations, and authorized reads
in auditFile. Unavailable audit storage blocks access that requires an audit record.
Use a separate persistent audit volume with protected retention and backups.

The Helm admin pod mounts published storage read-only and has no incoming volume.
It only writes audit records. Its sessions remain in memory and logout still
requires CSRF protection. Standalone YAML no longer requires incomingDir; the
legacy field is accepted for configuration compatibility and does not grant any
upload capability. Keep the standalone published directory read-only at the OS or
container boundary as well.
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

Published storage is shared read-only by admin and marketplace. Use
storage with shared file locks and atomic same-volume rename. RWX supports pods on
different nodes; RWO requires compatible node placement. Audit must be a separate
PVC. Admin UID/GID 10001 needs read access to published storage and write access
to audit storage. Importer alone requires published-volume writes and reads incoming.

Local tests exercise the real LDAP client over a synthetic LDAPS/StartTLS server,
untrusted certificates, nested-group filters, group revalidation, expired sessions,
CSRF/Origin, removed mutation endpoints for both roles, and audit failure.
Real organization AD and deployed ingress/storage verification remains
necessary when those environment values become available.
