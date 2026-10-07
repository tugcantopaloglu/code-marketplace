package storage_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"cdr.dev/slog"
	"github.com/stretchr/testify/require"

	"github.com/coder/code-marketplace/storage"
	"github.com/coder/code-marketplace/testutil"
)

func expectSignature(manifest *storage.VSIXManifest) {
	manifest.Assets.Asset = append(manifest.Assets.Asset, storage.VSIXAsset{
		Type:        storage.VSIXSignatureType,
		Path:        storage.SignatureZipFilename(manifest),
		Addressable: "true",
	})
}

//nolint:revive // test control flag
func signed(signer bool, factory func(t *testing.T) testStorage) func(t *testing.T) testStorage {
	return func(t *testing.T) testStorage {
		st := factory(t)
		key := false
		var exp func(*storage.VSIXManifest)
		if signer {
			key = true
			exp = expectSignature
		}

		return testStorage{
			storage:          storage.NewSignatureStorage(slog.Make(), key, st.storage),
			write:            st.write,
			exists:           st.exists,
			dir:              st.dir,
			expectedManifest: exp,
		}
	}
}

func TestDetachedSignatures(t *testing.T) {
	t.Parallel()
	for _, backend := range []struct {
		name    string
		factory storageFactory
	}{{"Local", localFactory}, {"Artifactory", artifactoryFactory}} {
		for _, emptySignatures := range []bool{false, true} {
			for _, platform := range []storage.Platform{"", storage.PlatformWin32X64, storage.PlatformLinuxX64} {
				t.Run(fmt.Sprintf("%s/empty=%t/platform=%s", backend.name, emptySignatures, platform), func(t *testing.T) {
					t.Parallel()
					ctx := context.Background()
					st := backend.factory(t)
					store := storage.NewSignatureStorage(slog.Make(), emptySignatures, st.storage)
					ext := testutil.Extensions[0].Copy()
					version := storage.Version{Version: ext.LatestVersion, TargetPlatform: platform}
					vsix := testutil.CreateVSIXFromExtension(t, ext, version)
					manifest, err := storage.ReadVSIXManifest(vsix)
					require.NoError(t, err)
					signature := testutil.CreateSignatureArchive(t, vsix)
					filename := storage.SignatureArchiveFilename(manifest)
					originalAssetCount := len(manifest.Assets.Asset)
					_, err = store.AddExtension(ctx, manifest, vsix, storage.File{RelativePath: filename, Content: signature})
					require.NoError(t, err)
					for range 2 {
						stored, err := store.Manifest(ctx, ext.Publisher, ext.Name, version)
						require.NoError(t, err)
						var signatures []storage.VSIXAsset
						for _, asset := range stored.Assets.Asset {
							if asset.Type == storage.VSIXSignatureType {
								signatures = append(signatures, asset)
							}
						}
						require.Equal(t, []storage.VSIXAsset{{Type: storage.VSIXSignatureType, Path: filename, Addressable: "true"}}, signatures)
					}
					require.Len(t, manifest.Assets.Asset, originalAssetCount)
					base := fmt.Sprintf("/%s/%s/%s/", ext.Publisher, ext.Name, version.String())
					for name, expected := range map[string][]byte{filename: signature, storage.ExtensionVSIXNameFromManifest(manifest) + ".vsix": vsix} {
						response := httptest.NewRecorder()
						store.FileServer().ServeHTTP(response, httptest.NewRequest(http.MethodGet, base+name, nil))
						require.Equal(t, http.StatusOK, response.Code)
						require.Equal(t, expected, response.Body.Bytes())
					}
					_, err = store.AddExtension(ctx, manifest, append(append([]byte(nil), vsix...), 1), storage.File{RelativePath: filename, Content: signature})
					require.ErrorContains(t, err, "does not match VSIX")
					ext.Description = "replacement package"
					updated := testutil.CreateVSIXFromExtension(t, ext, version)
					updatedManifest, err := storage.ReadVSIXManifest(updated)
					require.NoError(t, err)
					updatedSignature := testutil.CreateSignatureArchive(t, updated)
					_, err = store.AddExtension(ctx, updatedManifest, updated, storage.File{RelativePath: filename, Content: updatedSignature})
					require.NoError(t, err)
					stored, err := store.Manifest(ctx, ext.Publisher, ext.Name, version)
					require.NoError(t, err)
					require.Equal(t, "replacement package", stored.Metadata.Description)
					_, err = store.AddExtension(ctx, updatedManifest, updated)
					require.NoError(t, err)
					stored, err = store.Manifest(ctx, ext.Publisher, ext.Name, version)
					require.NoError(t, err)
					for _, asset := range stored.Assets.Asset {
						if asset.Type == storage.VSIXSignatureType {
							require.True(t, emptySignatures)
							require.Equal(t, storage.SignatureZipFilename(stored), asset.Path)
						}
					}
				})
			}
		}
	}
}
