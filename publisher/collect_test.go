package publisher_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/code-marketplace/publisher"
	"github.com/coder/code-marketplace/storage"
	"github.com/coder/code-marketplace/testutil"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func TestCollectBindsMarketplaceBytes(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ext := testutil.Extensions[0]
	version := storage.Version{Version: ext.LatestVersion, TargetPlatform: storage.PlatformWin32X64}
	vsix := testutil.CreateVSIXFromExtension(t, ext, version)
	signature := testutil.CreateSignatureArchive(t, vsix)
	for _, spoof := range []bool{false, true} {
		t.Run(map[bool]string{false: "authentic", true: "spoofed artifact"}[spoof], func(t *testing.T) {
			client := &http.Client{Transport: roundTrip(func(request *http.Request) (*http.Response, error) {
				require.Equal(t, "https", request.URL.Scheme)
				require.Equal(t, "marketplace.visualstudio.com", request.URL.Host)
				var data []byte
				switch {
				case request.Method == http.MethodPost:
					files := []any{map[string]any{"assetType": storage.VSIXAssetType, "source": publisher.Marketplace + "/assets/" + string(storage.VSIXAssetType) + "?targetPlatform=win32-x64"}, map[string]any{"assetType": storage.VSIXSignatureType, "source": publisher.Marketplace + "/assets/" + string(storage.VSIXSignatureType) + "?targetPlatform=win32-x64"}}
					data, err = json.Marshal(map[string]any{"results": []any{map[string]any{"extensions": []any{map[string]any{"extensionName": ext.Name, "publisher": map[string]any{"publisherId": uuid.NewString(), "publisherName": ext.Publisher, "displayName": "Publisher", "domain": "https://example.com", "isDomainVerified": true}, "versions": []any{map[string]any{"version": version.Version, "targetPlatform": version.TargetPlatform, "files": files}, storage.Version{Version: ext.LatestVersion}}}}}}})
					require.NoError(t, err)
				case strings.Contains(request.URL.Path, string(storage.VSIXAssetType)):
					require.Equal(t, "win32-x64", request.URL.Query().Get("targetPlatform"))
					data = vsix
					if spoof {
						changed := ext
						changed.Publisher = "impostor"
						data = testutil.CreateVSIXFromExtension(t, changed, version)
					}
				case strings.Contains(request.URL.Path, string(storage.VSIXSignatureType)):
					data = signature
				default:
					t.Fatalf("unexpected request %s", request.URL.Path)
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(data)), Request: request}, nil
			})}
			bundle, err := publisher.Collect(context.Background(), publisher.CollectOptions{Extension: ext.Publisher + "." + ext.Name, Platform: storage.PlatformWin32X64, KeyID: "collector", Key: private, Validity: time.Hour, Client: client})
			if spoof {
				require.ErrorContains(t, err, "does not match")
				return
			}
			require.NoError(t, err)
			require.Equal(t, vsix, bundle.VSIX)
			require.Equal(t, signature, bundle.Signature)
			policy := &publisher.Policy{Mode: "verified", Keys: map[string]ed25519.PublicKey{"collector": public}, MaxAge: 24 * time.Hour}
			_, err = policy.Verify(bundle.Report, vsix, signature, bundle.Manifest, time.Now().UTC())
			require.NoError(t, err)
		})
	}
}
