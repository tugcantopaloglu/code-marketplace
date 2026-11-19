package collector

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLocalServerProtectsMutations(t *testing.T) {
	s, err := New(context.Background(), "http://127.0.0.1:38117", Options{DataDir: t.TempDir()})
	require.NoError(t, err)
	tests := []struct {
		name, host, origin, token, body string
		code                            int
	}{
		{"foreign host", "attacker.example", s.origin, s.token, `{}`, 403},
		{"foreign origin", "127.0.0.1:38117", "https://attacker.example", s.token, `{}`, 403},
		{"no CSRF", "127.0.0.1:38117", s.origin, "", `{}`, 403},
		{"bad identity", "127.0.0.1:38117", s.origin, s.token, `{"ids":["../../evil"],"destination":"C:/tmp"}`, 400},
		{"relative destination", "127.0.0.1:38117", s.origin, s.token, `{"ids":["sample.hello"],"destination":"relative"}`, 400},
		{"unknown field", "127.0.0.1:38117", s.origin, s.token, `{"ids":["sample.hello"],"destination":"relative","signingKey":"x"}`, 400},
		{"trailing body", "127.0.0.1:38117", s.origin, s.token, `{} {}`, 400},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", s.origin+"/api/jobs", strings.NewReader(test.body))
			r.Host = test.host
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", test.origin)
			r.Header.Set("X-CSRF-Token", test.token)
			r.Header.Set("Authorization", "Bearer "+s.accessToken)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			require.Equal(t, test.code, w.Code, w.Body.String())
		})
	}
	request := httptest.NewRequest("GET", s.origin+"/api/session", nil)
	request.Header.Set("Authorization", "Bearer "+s.accessToken)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, request)
	require.Equal(t, 200, w.Code)
	require.NotContains(t, w.Body.String(), "PRIVATE KEY")
	require.Contains(t, w.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'")
	var value map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &value))
	require.Equal(t, s.token, value["csrfToken"])
	request.Header.Set("Sec-Fetch-Site", "cross-site")
	w = httptest.NewRecorder()
	s.ServeHTTP(w, request)
	require.Equal(t, 403, w.Code)
}

func TestCollectorKeyPersistsAcrossLaunches(t *testing.T) {
	directory := t.TempDir()
	a, keyA, err := configure(Options{DataDir: directory})
	require.NoError(t, err)
	b, keyB, err := configure(Options{DataDir: directory})
	require.NoError(t, err)
	require.Equal(t, a.KeyID, b.KeyID)
	require.Equal(t, keyA.Public().(ed25519.PublicKey), keyB.Public().(ed25519.PublicKey))
	require.FileExists(t, filepath.Join(directory, "collector-private.pem"))
	_, _, err = configure(Options{DataDir: t.TempDir(), Platform: "bogus"})
	require.Error(t, err)
	_, err = New(context.Background(), "http://0.0.0.0:38117", Options{DataDir: t.TempDir()})
	require.Error(t, err)
}

func TestCapabilityRequiredForEveryAPIEndpoint(t *testing.T) {
	s, err := New(context.Background(), "http://127.0.0.1:38117", Options{DataDir: t.TempDir()})
	require.NoError(t, err)
	for _, route := range []string{"/api/session", "/api/jobs", "/api/search?q=hello", "/api/jobs/unknown"} {
		for _, credential := range []string{"", "Bearer wrong", "Bearer " + s.token} {
			r := httptest.NewRequest("GET", s.origin+route, nil)
			r.Header.Set("Authorization", credential)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, r)
			require.Equal(t, 401, w.Code, route)
			require.NotContains(t, w.Body.String(), s.accessToken)
			require.NotContains(t, w.Body.String(), s.token)
		}
	}
	r := httptest.NewRequest("POST", s.origin+"/api/close", nil)
	r.Header.Set("Origin", s.origin)
	r.Header.Set("X-CSRF-Token", s.token)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	require.Equal(t, 401, w.Code)
	require.NoError(t, s.SaveLaunchURL())
	launch, err := os.ReadFile(filepath.Join(s.options.DataDir, "current-url.txt"))
	require.NoError(t, err)
	require.Equal(t, s.LaunchURL()+"\n", string(launch))
	other, err := New(context.Background(), s.origin, Options{DataDir: s.options.DataDir})
	require.NoError(t, err)
	require.NotEqual(t, s.accessToken, other.accessToken)
	for _, asset := range []string{"/", "/app.js", "/style.css"} {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, httptest.NewRequest("GET", s.origin+asset, nil))
		require.Equal(t, 200, w.Code)
		require.NotContains(t, w.Body.String(), s.accessToken)
	}
}

func TestPrivateConfigurationRejectsLinksAndOversizedFiles(t *testing.T) {
	file := filepath.Join(t.TempDir(), "oversized.pem")
	require.NoError(t, os.WriteFile(file, make([]byte, (64<<10)+1), 0o600))
	_, err := readPrivateFile(file)
	require.Error(t, err)
	_, err = readPrivateFile(t.TempDir())
	require.Error(t, err)
	link := filepath.Join(t.TempDir(), "linked.pem")
	if err := os.Symlink(file, link); err == nil {
		_, err := readPrivateFile(link)
		require.Error(t, err)
	}
}

func TestAtomicOutputsDoNotReplaceExistingBundles(t *testing.T) {
	folder := t.TempDir()
	require.NoError(t, atomicWrite(folder, "package.vsix", []byte("original"), false))
	require.Error(t, atomicWrite(folder, "package.vsix", []byte("replacement"), false))
	value, err := os.ReadFile(filepath.Join(folder, "package.vsix"))
	require.NoError(t, err)
	require.Equal(t, "original", string(value))
	require.Error(t, atomicWrite(folder, "../outside", []byte("no"), false))
	partials, err := filepath.Glob(filepath.Join(folder, "*.part"))
	require.NoError(t, err)
	require.Empty(t, partials)
}

func TestClosingRejectsNewDownloadsBeforeCreatingOutput(t *testing.T) {
	s, err := New(context.Background(), "http://127.0.0.1:38117", Options{DataDir: t.TempDir()})
	require.NoError(t, err)
	closeRequest := httptest.NewRequest("POST", s.origin+"/api/close", nil)
	closeRequest.Header.Set("Origin", s.origin)
	closeRequest.Header.Set("X-CSRF-Token", s.token)
	closeRequest.Header.Set("Authorization", "Bearer "+s.accessToken)
	closed := httptest.NewRecorder()
	s.ServeHTTP(closed, closeRequest)
	require.Equal(t, 200, closed.Code)
	destination := filepath.Join(t.TempDir(), "not-created")
	body, err := json.Marshal(map[string]any{"ids": []string{"sample.root"}, "destination": destination})
	require.NoError(t, err)
	request := httptest.NewRequest("POST", s.origin+"/api/jobs", strings.NewReader(string(body)))
	request.Header.Set("Origin", s.origin)
	request.Header.Set("X-CSRF-Token", s.token)
	request.Header.Set("Authorization", "Bearer "+s.accessToken)
	request.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, request)
	require.Equal(t, 409, w.Code)
	require.NoDirExists(t, destination)
}
