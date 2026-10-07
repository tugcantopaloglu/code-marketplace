# Implementation order

- [x] Require authenticated sandbox approval bound to the imported VSIX bytes.
- [x] Add configurable verified publisher admission, exact name/GUID allowlists, and signed offline publisher provenance from a connected collector.
- [x] Add incremental offline imports, durable receipts, conflict protection, and machine-readable results.
- [x] Harden the container and Helm deployment, including an optional offline import CronJob.
- [x] Verify local offline import, installation, updates, process restart persistence, and rejected packages.
- [ ] Run the container and live Kubernetes restart test after the local Docker engine is repaired.
- [x] Fix local catalog timestamps and report missing dependencies; validate platform assets.
- [x] Add the read-only management API and Graphite Mono UI with YAML, LDAPS or mandatory LDAP StartTLS, nested AD group access, secure sessions, and audit records.
- [x] Add complete offline image/chart/source bundles and an internal Harbor import/push helper.
- [ ] Validate organization AD group membership, CA trust, ingress, and shared PVC behavior in the actual internal environment.
- [ ] Transfer the generated offline bundle and push it to the organization's Harbor using its host, project, credentials, and TLS CA.

The Nextron THOR adapter remains pending until its version and a native JSON scan report are provided. Its licensed scanner runs on a fixed host outside the marketplace deployment.

Artifactory timestamp migration is outside the offline PVC deployment work.
