package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cdr.dev/slog"
	"github.com/coder/code-marketplace/ingest"
	"github.com/coder/code-marketplace/publisher"
	"github.com/coder/code-marketplace/storage"
	"github.com/coder/code-marketplace/testutil"
	"github.com/stretchr/testify/require"
)

type simulationTransport struct{ base *url.URL }

func (s simulationTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	copy := request.Clone(request.Context())
	target := *request.URL
	target.Scheme = s.base.Scheme
	target.Host = s.base.Host
	target.Path = strings.TrimRight(s.base.Path, "/") + request.URL.Path
	copy.URL = &target
	copy.Host = s.base.Host
	return http.DefaultTransport.RoundTrip(copy)
}

// This is opt-in and uses a running Postman simulation over real HTTP. The
// production code retains its trusted HTTPS URLs; only this test's transport
// maps those requests to the loopback simulation. It does not claim TLS trust.
func TestCollectorAgainstPostmanSimulation(t *testing.T) {
	address := os.Getenv("COLLECTOR_SIMULATION_URL")
	if address == "" {
		t.Skip("start postman simulation and set COLLECTOR_SIMULATION_URL")
	}
	fixtures := make(map[string][]byte, 6)
	for _, name := range []string{"root", "dep", "extra"} {
		ext := testutil.Extensions[0].Copy()
		ext.Publisher = "sample"
		ext.Name = name
		ext.Properties = nil
		if name == "root" {
			ext.Properties = []storage.VSIXProperty{{ID: storage.DependencyPropertyType, Value: "sample.dep,vscode.git"}, {ID: storage.PackPropertyType, Value: "sample.dep,sample.extra"}}
		}
		if name == "extra" {
			ext.Properties = []storage.VSIXProperty{{ID: storage.DependencyPropertyType, Value: "sample.root"}}
		}
		vsix := testutil.CreateVSIXFromExtension(t, ext, storage.Version{Version: "1.0.0"})
		fixtures[name+".vsix"] = vsix
		fixtures[name+".sigzip"] = testutil.CreateSignatureArchive(t, vsix)
	}
	base, err := url.Parse(address)
	require.NoError(t, err)
	fixtureJSON, err := json.Marshal(fixtures)
	require.NoError(t, err)
	control := &http.Client{Timeout: 5 * time.Second}
	response, err := control.Post(address+"/control/fixtures", "application/json", bytes.NewReader(fixtureJSON))
	require.NoError(t, err)
	response.Body.Close()
	require.Equal(t, 200, response.StatusCode)
	setMode := func(mode string) {
		response, err := control.Post(address+"/control/mode", "application/json", strings.NewReader(`{"mode":"`+mode+`"}`))
		require.NoError(t, err)
		require.Equal(t, 200, response.StatusCode)
		response.Body.Close()
	}
	defer setMode("normal")
	for _, mode := range []string{"normal", "bad-signature", "unavailable", "slow"} {
		t.Run(mode, func(t *testing.T) {
			setMode(mode)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			server := httptest.NewUnstartedServer(nil)
			origin := "http://" + server.Listener.Addr().String()
			options := Options{DataDir: t.TempDir(), Client: &http.Client{Transport: simulationTransport{base}, Timeout: time.Second}}
			app, err := New(ctx, origin, options)
			require.NoError(t, err)
			server.Config.Handler = app
			server.Start()
			defer server.Close()
			defer func() { cancel(); app.Wait() }()
			call := func(method, route string, body any, output any) int {
				data, _ := json.Marshal(body)
				request, err := http.NewRequest(method, server.URL+route, bytes.NewReader(data))
				require.NoError(t, err)
				request.Header.Set("Origin", origin)
				request.Header.Set("X-CSRF-Token", app.token)
				request.Header.Set("Authorization", "Bearer "+app.accessToken)
				request.Header.Set("Content-Type", "application/json")
				response, err := http.DefaultClient.Do(request)
				require.NoError(t, err)
				defer response.Body.Close()
				if output != nil {
					require.NoError(t, json.NewDecoder(response.Body).Decode(output))
				} else {
					_, _ = io.Copy(io.Discard, response.Body)
				}
				return response.StatusCode
			}
			if mode == "unavailable" {
				var result map[string]string
				require.Equal(t, 502, call("GET", "/api/search?q=sample", nil, &result))
				require.Contains(t, result["error"], "Marketplace")
				return
			}
			if mode == "normal" {
				var result publisher.SearchResult
				require.Equal(t, 200, call("GET", "/api/search?q=sample", nil, &result))
				require.Len(t, result.Entries, 3)
				require.True(t, result.Entries[0].Verified)
			}
			var job Job
			destination := t.TempDir()
			require.Equal(t, 202, call("POST", "/api/jobs", map[string]any{"ids": []string{"sample.root", "SAMPLE.root"}, "destination": destination}, &job))
			if mode == "slow" {
				require.Eventually(t, func() bool { var value Job; call("GET", "/api/jobs/"+job.ID, nil, &value); return value.Current != "" }, time.Second, 20*time.Millisecond)
				require.Equal(t, 200, call("POST", "/api/jobs/"+job.ID+"/cancel", nil, nil))
			}
			require.Eventually(t, func() bool {
				require.Equal(t, 200, call("GET", "/api/jobs/"+job.ID, nil, &job))
				return job.Status != "running"
			}, 15*time.Second, 30*time.Millisecond)
			require.FileExists(t, filepath.Join(job.Folder, "SHA256SUMS"))
			if mode == "normal" {
				require.Equal(t, "completed", job.Status)
				require.Equal(t, 3, job.Completed)
				require.Len(t, job.Results, 3)
				files, err := filepath.Glob(filepath.Join(job.Folder, "incoming", "*.vsix"))
				require.NoError(t, err)
				require.Len(t, files, 3)
				policy, err := publisher.LoadPolicy(filepath.Join(job.Folder, "publisher-policy-allowlist.json"), "allowlist", 7*24*time.Hour)
				require.NoError(t, err)
				result, err := ingest.Run(context.Background(), ingest.Options{Incoming: filepath.Join(job.Folder, "incoming"), Storage: t.TempDir(), SandboxMode: "disabled", PublisherPolicy: policy, Logger: slog.Make()})
				require.NoError(t, err)
				require.Len(t, result.Results, 3)
				for _, entry := range result.Results {
					require.Equal(t, "imported", entry.Status)
				}
				privateFiles, err := filepath.Glob(filepath.Join(job.Folder, "*.pem"))
				require.NoError(t, err)
				require.Empty(t, privateFiles)
			} else {
				if mode == "slow" {
					require.Equal(t, "canceled", job.Status)
				} else {
					require.Equal(t, "failed", job.Status)
				}
				files, err := filepath.Glob(filepath.Join(job.Folder, "incoming", "*.vsix"))
				require.NoError(t, err)
				require.Empty(t, files)
			}
		})
	}
}
