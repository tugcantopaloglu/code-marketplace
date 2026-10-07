package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"cdr.dev/slog"
	"github.com/stretchr/testify/require"

	"github.com/coder/code-marketplace/api"
	"github.com/coder/code-marketplace/database"
	"github.com/coder/code-marketplace/storage"
	"github.com/coder/code-marketplace/testutil"
)

func TestSignatureAssets(t *testing.T) {
	t.Parallel()
	for _, emptySignatures := range []bool{false, true} {
		t.Run(fmt.Sprintf("empty=%t", emptySignatures), func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			logger := slog.Make()
			store, err := storage.NewStorage(ctx, &storage.Options{ExtDir: t.TempDir(), Logger: logger, IncludeEmptySignatures: emptySignatures})
			require.NoError(t, err)
			ext := testutil.Extensions[0]
			version := storage.Version{Version: ext.LatestVersion, TargetPlatform: storage.PlatformWin32X64}
			vsix := testutil.CreateVSIXFromExtension(t, ext, version)
			manifest, err := storage.ReadVSIXManifest(vsix)
			require.NoError(t, err)
			signature := testutil.CreateSignatureArchive(t, vsix)
			_, err = store.AddExtension(ctx, manifest, vsix, storage.File{RelativePath: storage.SignatureArchiveFilename(manifest), Content: signature})
			require.NoError(t, err)
			server := httptest.NewServer(api.New(&api.Options{
				Database: &database.NoDB{Storage: store, Logger: logger},
				Storage:  store,
				Logger:   logger,
			}).Handler)
			t.Cleanup(server.Close)
			request, err := json.Marshal(api.QueryRequest{
				Filters: []database.Filter{{
					Criteria: []database.Criteria{{Type: database.ExtensionName, Value: ext.Publisher + "." + ext.Name}},
					PageSize: 10,
				}},
				Flags: database.IncludeVersions | database.IncludeFiles | database.IncludeAssetURI,
			})
			require.NoError(t, err)
			response, err := http.Post(server.URL+"/api/extensionquery", "application/json", bytes.NewReader(request))
			require.NoError(t, err)
			t.Cleanup(func() { response.Body.Close() })
			require.Equal(t, http.StatusOK, response.StatusCode)
			var result api.QueryResponse
			require.NoError(t, json.NewDecoder(response.Body).Decode(&result))
			require.Len(t, result.Results, 1)
			require.Len(t, result.Results[0].Extensions, 1)
			require.Len(t, result.Results[0].Extensions[0].Versions, 1)
			var signatureURL string
			for _, asset := range result.Results[0].Extensions[0].Versions[0].Files {
				if asset.Type == storage.VSIXSignatureType {
					require.Empty(t, signatureURL)
					signatureURL = asset.Source
				}
			}
			require.NotEmpty(t, signatureURL)
			for _, url := range []string{
				signatureURL,
				fmt.Sprintf("%s/assets/%s/%s/%s/%s", server.URL, ext.Publisher, ext.Name, version.String(), storage.VSIXSignatureType),
				fmt.Sprintf("%s/api/publishers/%s/vsextensions/%s/%s/%s", server.URL, ext.Publisher, ext.Name, version.String(), storage.VSIXSignatureType),
			} {
				response, err := http.Get(url)
				require.NoError(t, err)
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, response.StatusCode)
				require.Equal(t, signature, body)
			}
		})
	}
}
