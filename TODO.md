# Implementation order

- [x] Require authenticated sandbox approval bound to the imported VSIX bytes.
- [x] Add incremental offline imports, durable receipts, conflict protection, and machine-readable results.
- [x] Harden the container and Helm deployment, including an optional offline import CronJob.
- [x] Verify local offline import, installation, updates, process restart persistence, and rejected packages.
- [ ] Run the container and live Kubernetes restart test after the local Docker engine is repaired.
- [x] Fix local catalog timestamps and report missing dependencies; validate platform assets.
- [ ] Add the management API and UI last, with LDAPS or LDAP with StartTLS, AD group authorization, secure sessions, and audit records.

The Nextron THOR adapter remains pending until its version and a native JSON scan report are provided. Its licensed scanner runs on a fixed host outside the marketplace deployment.

Artifactory timestamp migration is outside the offline PVC deployment work.
