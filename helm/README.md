# Code Extension Marketplace Helm Chart

Optional AD management is configured using `values-admin.yaml` together with
offline values. See [MANAGEMENT.md](../MANAGEMENT.md) for YAML settings, secure
LDAP, Secrets, ingress restrictions, and read-only PVC access. See
[OFFLINE.md](../OFFLINE.md) for complete offline bundles and internal Harbor pushes.
The admin component is disabled by default and uses the same application image.

Deploy the fork image from your internal registry. The chart defaults to
`v2.6.0`; build and mirror that image, or set `image.tag` to the exact release
or commit image you built. The chart does not create or download that image.

```console
helm upgrade --install code-marketplace ./helm --namespace code-marketplace -f ./helm/values-offline.yaml
```

Replace the example registry, PVC names, ingress hostname, TLS Secret, and
controller namespace in `values-offline.yaml` before deployment. Storage class
and ingress class remain configurable.

## Offline import

The marketplace mounts published storage read-only. The optional CronJob mounts
incoming storage read-only and published storage writable. It executes the
mandatory sandbox-gated `import` command with no network access. Keep your
existing scheduler by leaving `importer.enabled: false` and invoking the same
command there. Do not run two independent schedulers for the same storage.

Create the incoming PVC separately and use `importer.incoming.existingClaim`.
Use `persistence.existingClaim` for an existing published PVC. Otherwise the chart
creates a published PVC using `persistence.accessModes`, `persistence.size`, and
an optional `persistence.storageClass`. An omitted storage class uses the cluster
default. `subPath` values allow distinct pre-created directories on shared storage.
The incoming and published directories must not refer to the same directory.

The chart defaults to one replica and `ReadWriteOnce`. A CronJob and server on
different nodes require storage that supports their concurrent mounts, or explicit
node placement for a single-node mount. Select appropriate RWX storage and verify
shared native file locks and atomic renames before enabling the importer across
nodes. The chart does not assume that your storage class supports those operations.

Deploy the scanner public keys as a trusted ConfigMap, separate from the share:

```console
kubectl --namespace code-marketplace create configmap marketplace-sandbox-trust --from-file=sandbox-trust.json=./sandbox-trust.json
```

Set `importer.sandboxTrust.configMap` to that name. The sandbox signing private
key, THOR binary, THOR license, and scanner rule updates stay on the dedicated
licensed scanner server. See [SANDBOX.md](../SANDBOX.md).

Publisher admission defaults to `importer.publisherPolicy.mode: verified`.
Create `marketplace-publisher-policy` from the connected collector's public
`publisher-policy.json`, then configure its exact publisher-name or GUID
allowlist. Set `mode: allowlist` to accept allowlisted publishers without requiring
the badge, or explicitly set `mode: any` to disable publisher restrictions.
VSIX signature checks remain required. Sandbox admission defaults to
`importer.sandboxMode: required`. To temporarily operate without a scanner, set
`importer.sandboxMode: disabled`; the chart omits the sandbox trust volume and its
arguments. Verified Publisher admission and its allowlist continue to apply.
The collector's private key
stays on the connected host. See [PUBLISHERS.md](../PUBLISHERS.md).

The importer produces JSON logs with per-file decisions. Missing sidecars wait;
policy rejections do not stop other packages. Infrastructure failures and
conflicting existing versions make the Job fail. `concurrencyPolicy: Forbid`
prevents overlap for this CronJob; a native shared lock also guards the storage.

## HTTPS and network access

Expose the root of a hostname over HTTPS with a certificate trusted by VS Code
clients. Set `ingress.className`, hosts, and TLS Secret for your controller. Its
proxy must set `Forwarded`, or `X-Forwarded-Host` and `X-Forwarded-Proto`, so
package and signature asset URLs also use HTTPS. Verify this in an
`/api/extensionquery` response. A browser GET to `/api` alone is not a query.

NetworkPolicy is enabled by default, allows incoming traffic from pods in the
same namespace, and denies pod egress. For an ingress controller in a different
namespace, configure `networkPolicy.ingressFrom` to select that namespace or its
specific pods. The example uses `ingress-system`; change it to your actual
controller namespace. Network isolation requires a CNI that enforces policies.
For Artifactory mode, explicitly permit its internal endpoint and DNS in
`networkPolicy.egress`; the offline importer only supports local PVC storage.

## Runtime and operations

Containers use UID/GID 10001, a read-only root filesystem, no privilege escalation,
no Linux capabilities, RuntimeDefault seccomp, and no service-account token.
The default filesystem group is 10001. Set volume permissions or `fsGroup` to
match the storage provisioner. Service port 80 forwards to container port 8080.
Configure resource values for the actual catalog and maximum package sizes.

`/healthz` checks process health. `/readyz` additionally checks local storage
readability. Startup, readiness, and liveness probes are included. The catalog
cache defaults to 30 seconds; set `server.listCacheDuration` as needed. Import
receipts and catalog dates are private stored metadata and are not download assets.

Helm test pods are optional (`tests.enabled: true`) and use the same internal
marketplace image. No additional public BusyBox image is needed. Their network
policy allows only the marketplace and cluster DNS.

Back up the published PVC and trusted public-key configuration before upgrades.
Restore the stored VSIX, signature, receipt, sandbox report, and catalog metadata
together. External PVCs are not deleted by Helm; a chart-created PVC is a release
resource, so preserve or back it up before uninstalling. `helm uninstall` is not
a backup or rollback procedure.

```console
helm lint ./helm
helm lint ./helm -f ./helm/values-offline.yaml
helm template code-marketplace ./helm -f ./helm/values-offline.yaml
```
