set -eu

version="${1:?Usage: bash scripts/export-offline.sh VERSION OUTPUT_DIR [amd64|arm64]}"
output="${2:?Output directory required}"
architecture="${3:-amd64}"
case "$architecture" in amd64|arm64) ;; *) exit 2 ;; esac
if ! printf '%s' "$version" | grep -Eq '^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$'; then exit 2; fi
git diff --quiet
git diff --cached --quiet
test -z "$(git ls-files --others --exclude-standard)"
test ! -e "$output"
mkdir -p "$output"
output="$(cd "$output" && pwd)"
revision="$(git rev-parse HEAD)"
image="code-marketplace:${version}-${architecture}"
source_url="${SOURCE_URL:-https://github.com/tugcantopaloglu/code-marketplace}"
CGO_ENABLED=0 GOOS=linux GOARCH="$architecture" go build -trimpath -ldflags "-X github.com/coder/code-marketplace/buildinfo.tag=${version}" -o "bin/code-marketplace-linux-${architecture}" ./cmd/marketplace
docker build --platform "linux/${architecture}" --build-arg "TARGETARCH=${architecture}" --label "org.opencontainers.image.source=${source_url}" --label "org.opencontainers.image.revision=${revision}" --label "org.opencontainers.image.version=${version}" --label "org.opencontainers.image.licenses=AGPL-3.0" -t "$image" .
docker run --rm --pull=never --platform "linux/${architecture}" --network none --read-only --cap-drop ALL --security-opt no-new-privileges "$image" version
docker run --rm --pull=never --platform "linux/${architecture}" --network none --read-only --cap-drop ALL --security-opt no-new-privileges "$image" admin --help
docker save "$image" | gzip > "$output/image.tar.gz"
docker image inspect "$image" --format '{{.Id}}' > "$output/image-id.txt"
printf '%s\n' "$image" > "$output/image-reference.txt"
printf '%s\n' "$revision" > "$output/source-revision.txt"
helm lint --strict ./helm -f ./helm/values-offline.yaml -f ./helm/values-admin.yaml
helm package ./helm --app-version "$version" --destination "$output"
git archive --format=tar.gz --output="$output/source.tar.gz" HEAD
cp LICENSE NOTICE OFFLINE.md MANAGEMENT.md helm/values-offline.yaml helm/values-admin.yaml scripts/import-harbor.ps1 "$output/"
cd "$output"
sha256sum image.tar.gz image-id.txt image-reference.txt source-revision.txt source.tar.gz code-marketplace-*.tgz LICENSE NOTICE OFFLINE.md MANAGEMENT.md values-offline.yaml values-admin.yaml import-harbor.ps1 > SHA256SUMS
