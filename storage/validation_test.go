package storage_test

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coder/code-marketplace/storage"
	"github.com/coder/code-marketplace/testutil"
	"github.com/stretchr/testify/require"
)

func TestIdentityCannotEscapeStorage(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"../outside", "..\\outside", "/absolute", "C:drive", ".", "..", "CON", "name.", "bad\x00name"} {
		t.Run(value, func(t *testing.T) {
			st := localFactory(t)
			manifest := testutil.ConvertExtensionToManifest(testutil.Extensions[0], storage.Version{Version: "1.0.0"})
			manifest.Metadata.Identity.Publisher = value
			vsix := testutil.CreateVSIXFromManifest(t, manifest)
			_, err := st.storage.AddExtension(context.Background(), manifest, vsix)
			require.Error(t, err)
			entries, err := os.ReadDir(st.dir)
			require.NoError(t, err)
			require.Empty(t, entries)
		})
	}
}

func TestFailedImportIsNotPublished(t *testing.T) {
	st := localFactory(t)
	manifest := testutil.ConvertExtensionToManifest(testutil.Extensions[0], storage.Version{Version: "1.0.0"})
	vsix := testutil.CreateVSIXFromManifest(t, manifest)
	_, err := st.storage.AddExtension(context.Background(), manifest, vsix, storage.File{RelativePath: "../escape", Content: []byte("x")})
	require.Error(t, err)
	require.NoFileExists(t, filepath.Join(st.dir, "escape"))
	versions, err := st.storage.Versions(context.Background(), manifest.Metadata.Identity.Publisher, manifest.Metadata.Identity.ID)
	if err == nil {
		require.Empty(t, versions)
	}
}

func TestCorruptArchivePreservesPublishedVersion(t *testing.T) {
	t.Parallel()
	st := localFactory(t)
	ext := testutil.Extensions[0]
	manifest := testutil.ConvertExtensionToManifest(ext, storage.Version{Version: ext.LatestVersion})
	original := testutil.CreateVSIXFromManifest(t, manifest)
	_, err := st.storage.AddExtension(context.Background(), manifest, original)
	require.NoError(t, err)
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for name, data := range map[string][]byte{
		"extension.vsixmanifest": testutil.ConvertExtensionToManifestBytes(t, ext, storage.Version{Version: ext.LatestVersion}),
		"corrupt.txt":            []byte("CRC_CHECK_PAYLOAD"),
	} {
		entry, err := writer.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		require.NoError(t, err)
		_, err = entry.Write(data)
		require.NoError(t, err)
	}
	require.NoError(t, writer.Close())
	corrupt := buffer.Bytes()
	position := bytes.Index(corrupt, []byte("CRC_CHECK_PAYLOAD"))
	require.NotEqual(t, -1, position)
	corrupt[position] ^= 1
	_, err = st.storage.AddExtension(context.Background(), manifest, corrupt)
	require.Error(t, err)
	stored, err := os.ReadFile(filepath.Join(st.dir, ext.Publisher, ext.Name, ext.LatestVersion, storage.ExtensionVSIXNameFromManifest(manifest)+".vsix"))
	require.NoError(t, err)
	require.Equal(t, original, stored)
	entries, err := os.ReadDir(st.dir)
	require.NoError(t, err)
	for _, entry := range entries {
		require.False(t, strings.HasPrefix(entry.Name(), ".import-") || strings.HasPrefix(entry.Name(), ".previous-"))
	}
}
