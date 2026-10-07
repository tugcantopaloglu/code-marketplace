# Offline image delivery to Harbor

Build once on a connected Linux machine or the repository's `offline bundle`
workflow, then transfer the resulting files into the internal network. Runtime
does not download Go modules, container layers, charts, JS, fonts, or external assets.
The optional admin only connects to the configured internal AD and DNS endpoints.
THOR stays on its separately licensed scanner host.

## Create a bundle

The connected builder needs Git, the Go version from `go.mod`, Docker, and Helm.
Use a clean committed checkout so the supplied source matches the image:

```console
bash scripts/export-offline.sh v2.6.0 ./offline-output amd64
```

Use `arm64` for ARM nodes. The image is single-architecture; mixed-node clusters
need separate repositories/tags or an explicitly assembled multi-architecture
Harbor manifest. The script validates the architecture/tag, builds the static Go
binary and final image, and writes:

- `image.tar.gz`, a Docker image archive including all runtime layers.
- Image reference/ID and exact Git source revision.
- The packaged Helm chart, example offline/admin values, and usage documentation.
- `source.tar.gz`, corresponding repository source, license, attribution, and build scripts.
- `SHA256SUMS` and a PowerShell Harbor import helper.

The workflow produces both architecture bundles as downloadable artifacts without
publishing a release or writing to Harbor. Run it with an immutable version string.
Keep and provide the corresponding source alongside deployed images as required
by the application's AGPL-3.0 license. Dependency license texts are included in
the image and source. Refresh `licenses/` when adding or upgrading dependencies.

Transfer the complete bundle using the organization's authorized process. Checksums
detect corruption; they do not authenticate a maliciously replaced bundle and checksum
manifest. Obtain the files from the trusted build run and protect the transfer path.

## Load and push inside the internal network

The internal import machine needs Docker, connectivity to Harbor, permission to push
to the selected private project, and trust for Harbor's TLS CA. Create the Harbor
project and log in using a scoped robot account or authorized user:

```console
docker login harbor.internal
pwsh -File ./import-harbor.ps1 -BundleDirectory ./bundle -Repository harbor.internal/development/code-marketplace -Tag v2.6.0-amd64
```

The helper verifies every listed checksum, loads the compressed archive, verifies
the loaded image ID, tags it for Harbor, and pushes it. Credentials are handled by
Docker login rather than passed in script arguments. The equivalent Linux steps are:

```console
cd bundle
sha256sum -c SHA256SUMS
docker load --input image.tar.gz
docker image inspect "$(cat image-reference.txt)" --format '{{.Id}}'
cat image-id.txt
docker tag "$(cat image-reference.txt)" harbor.internal/development/code-marketplace:v2.6.0-amd64
docker login harbor.internal
docker push harbor.internal/development/code-marketplace:v2.6.0-amd64
```

Confirm the inspect ID equals `image-id.txt` before tagging/pushing. Use HTTPS and
install the organization's Harbor CA into the Docker daemon/node trust stores.
Do not configure an insecure registry as a substitute. Record the digest returned
by the push and enable Harbor tag immutability for deployment tags.
See [Harbor image operations](https://goharbor.io/docs/main/working-with-projects/working-with-images/pulling-pushing-images/)
and [Docker image save](https://docs.docker.com/reference/cli/docker/image/save/).

## Install from the internal image

Create a Kubernetes image pull Secret using a protected existing Docker config:

```console
kubectl create secret generic harbor-pull --type=kubernetes.io/dockerconfigjson --from-file=.dockerconfigjson=./config.json
```

Configure `image.repository`, `image.tag`, and `imagePullSecrets` in the values YAML:

```yaml
image:
  repository: harbor.internal/development/code-marketplace
  tag: v2.6.0-amd64
  pullPolicy: IfNotPresent
imagePullSecrets:
  - name: harbor-pull
```

Supply the actual PVCs, trust ConfigMaps, ingress/TLS, AD values, and NetworkPolicy
peers described in `MANAGEMENT.md` and `helm/README.md`. Preserve the chart's nonroot,
read-only-root, dropped-capability and service-account restrictions. Use the bundled
chart file instead of fetching a remote chart:

```console
helm upgrade --install marketplace ./code-marketplace-1.6.0.tgz -f ./values-offline.yaml -f ./values-admin.yaml -f ./values-internal.yaml
```

The same image serves marketplace, importer, management, and optional chart tests.
There are no extra public runtime images to mirror. Harbor details and organization
secrets are environment inputs; neither the export workflow nor the repository
pushes to an unknown internal registry automatically.
