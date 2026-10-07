# Existing shared-folder deployments

Preserve the bound PVC and existing Service/Ingress names when upgrading a manual
deployment. Use raw manifests for that deployment rather than implicitly adopting
its resources into a new Helm release. Keep its UID/GID, public port, TLS Secret,
and storage node placement until the current layout is verified.

Rollback must also serve an isolated catalog root. A saved legacy Deployment or
rollout undo that restores a whole-volume public mount can expose newly created
audit or incoming data. Prepare a clean root from preserved legacy publisher
directories and keep the read-only subPath boundary when changing images.

Separate operational directories from the published storage root:

```text
volume/
  incoming/
  published/
  audit/
  processed/
  hatali/
  original-publisher-directories/
```

The marketplace mounts only `published` read-only. The mandatory gated importer
mounts sibling `incoming` read-only and `published` writable. Admin mounts only
`published` read-only and `audit` writable. A shared PVC with sibling subPaths can
provide these mounts; never expose the whole volume through the public file server.
Restrict share users' write permissions to incoming; published storage, audit, and
trusted configuration are controlled by service identities and trusted operators.

A host directory may already be an NFS mount on every node while its Kubernetes
PV is declared `local` with nodeAffinity. That declaration still constrains pod
placement. Keep the existing bound PV during the application upgrade. A subsequent
conversion to a formal NFS/RWX PV/PVC needs separate storage planning. See
[local volume scheduling](https://kubernetes.io/docs/concepts/storage/volumes/#local)
and [access modes](https://kubernetes.io/docs/concepts/storage/persistent-volumes/#access-modes).

Suspend the old scheduler and wait for existing jobs to finish before taking a
storage backup/snapshot and copying data. CronJob suspension does not stop active
jobs. See [CronJob suspension](https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/#schedule-suspension).
Keep the original Deployment/Service/Ingress/CronJob YAML for rollback.

`scripts/prepare-local-volume.sh --inventory /volume` lists candidate publisher
directories with version manifests, excluding operational directories. Review the
list; inventory does not establish sandbox or publisher approval. Save reviewed
publisher names one per line in a UTF-8 text file:

```console
sh scripts/prepare-local-volume.sh /volume ./publishers.txt
```

Copy mode defaults to UID 1000. Set `MARKETPLACE_UID` only if the actual deployment
uses a different UID. The script checks paths, symlinks, duplicates, destination
collisions, and free space; copies into private staging; compares bytes before
publishing; and preserves all source directories. Run it with all writers stopped.
It does not delete old data, create approvals, or overwrite existing targets.
Failed staging is retained for inspection. A failed or partial run needs operator
review before retrying. Source preservation is not a replacement for a backup.

Point the upgraded marketplace at `published` only after successful copy. Existing
versions remain legacy catalog entries; missing signatures or import receipts are
not manufactured by migration. Reimporting a legacy version through the gated
importer can conflict with its missing receipt. Review and migrate those versions
explicitly; upgrades do not retroactively scan or authenticate old packages.

Reuse one scheduler, replacing `add` and VSIX-only file moves with `import` and
trusted sandbox/publisher policy mounts. Keep it suspended until authentic reports
and public keys are ready. Test one package with matching `.vsix`, `.sigzip`,
`.publisher.json`, and `.sandbox.json`, then enable the schedule. Imported inputs
remain on the share; archive full file groups through a separate trusted procedure.
Retain scheduler logs as well as the private latest-import summary.
