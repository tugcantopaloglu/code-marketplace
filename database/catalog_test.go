package database_test

import (
	"context"
	"net/url"
	"testing"
	"time"

	"cdr.dev/slog"
	"github.com/coder/code-marketplace/database"
	"github.com/coder/code-marketplace/storage"
	"github.com/coder/code-marketplace/testutil"
	"github.com/stretchr/testify/require"
)

func TestLocalCatalogDatesAndPlatforms(t *testing.T) {
	ctx := context.Background()
	store, err := storage.NewStorage(ctx, &storage.Options{ExtDir: t.TempDir(), Logger: slog.Make()})
	require.NoError(t, err)
	ext := testutil.Extensions[0]
	for _, platform := range []storage.Platform{storage.PlatformWin32X64, storage.PlatformLinuxX64} {
		version := storage.Version{Version: ext.LatestVersion, TargetPlatform: platform}
		vsix := testutil.CreateVSIXFromExtension(t, ext, version)
		manifest, err := storage.ReadVSIXManifest(vsix)
		require.NoError(t, err)
		_, err = store.AddExtension(ctx, manifest, vsix, storage.File{RelativePath: storage.SignatureArchiveFilename(manifest), Content: testutil.CreateSignatureArchive(t, vsix)})
		require.NoError(t, err)
	}
	db := &database.NoDB{Storage: store, Logger: slog.Make()}
	query := database.Filter{Criteria: []database.Criteria{{Type: database.ExtensionName, Value: ext.Publisher + "." + ext.Name}}, PageSize: 10}
	base, err := url.Parse("https://marketplace.internal")
	require.NoError(t, err)
	results, count, err := db.GetExtensions(ctx, query, database.IncludeLatestVersionOnly|database.IncludeFiles|database.IncludeAssetURI, *base)
	require.NoError(t, err)
	require.Equal(t, 1, count)
	require.Len(t, results, 1)
	require.WithinDuration(t, time.Now().UTC(), results[0].PublishedDate, time.Minute)
	require.WithinDuration(t, time.Now().UTC(), results[0].LastUpdated, time.Minute)
	require.Len(t, results[0].Versions, 2)
	for _, version := range results[0].Versions {
		require.WithinDuration(t, time.Now().UTC(), version.LastUpdated, time.Minute)
		require.Contains(t, version.AssetURI, version.Version.String())
		for _, file := range version.Files {
			if file.Type == storage.VSIXSignatureType {
				require.Contains(t, file.Source, version.Version.String())
			}
		}
	}
}
