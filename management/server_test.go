package management

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"cdr.dev/slog"
	"github.com/coder/code-marketplace/storage"
	"github.com/coder/code-marketplace/testutil"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type testAuth struct {
	user     User
	denied   bool
	password string
}

func (a *testAuth) Authenticate(_ context.Context, username, password string) (User, error) {
	if a.denied || username != a.user.Name || password != a.password {
		return User{}, fmt.Errorf("denied")
	}
	return a.user, nil
}

func (a *testAuth) Authorize(_ context.Context, _ User) (User, error) {
	if a.denied {
		return User{}, fmt.Errorf("denied")
	}
	return a.user, nil
}

func testConfig(t *testing.T) Config {
	t.Helper()
	base := t.TempDir()
	for _, name := range []string{"published", "incoming", "audit", "trusted"} {
		require.NoError(t, os.Mkdir(filepath.Join(base, name), 0o700))
	}
	password := filepath.Join(base, "trusted", "password")
	require.NoError(t, os.WriteFile(password, []byte("test-bind-password"), 0o600))
	return Config{Address: "127.0.0.1:8081", PublicURL: "https://admin.example", ExtensionsDir: filepath.Join(base, "published"), IncomingDir: filepath.Join(base, "incoming"), AuditFile: filepath.Join(base, "audit", "audit.jsonl"), LDAP: LDAPConfig{URL: "ldaps://dc.example:636", BindDN: "CN=service,DC=example", BindPasswordFile: password, UserBaseDN: "OU=Users,DC=example", UsernameAttribute: "sAMAccountName", AdminGroups: []string{"CN=Admins,DC=example"}, ReaderGroups: []string{"CN=Readers,DC=example"}, Timeout: time.Second}, Session: SessionConfig{Lifetime: time.Hour, IdleTimeout: 15 * time.Minute, RecheckInterval: time.Minute, MaxSessions: 100}, Publisher: PublisherConfig{Mode: "any", MaxAge: time.Hour}}
}

func testServer(t *testing.T, role string) (*Server, *testAuth) {
	t.Helper()
	auth := &testAuth{user: User{Name: "alice", DN: "CN=Alice,OU=Users,DC=example", Role: role}, password: "test-user-password"}
	server, err := New(testConfig(t), auth)
	require.NoError(t, err)
	return server, auth
}

func call(server *Server, method, path, body string, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, server.config.PublicURL+"/admin/api/"+path, strings.NewReader(body))
	req.Header.Set("Origin", server.config.PublicURL)
	req.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	response := httptest.NewRecorder()
	server.ServeHTTP(response, req)
	return response
}

func signIn(t *testing.T, server *Server) (*http.Cookie, string) {
	t.Helper()
	response := call(server, http.MethodPost, "login", `{"username":"alice","password":"test-user-password"}`, nil, "")
	require.Equal(t, http.StatusOK, response.Code, response.Body.String())
	var data struct {
		CSRF string `json:"csrfToken"`
	}
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &data))
	cookies := response.Result().Cookies()
	require.Len(t, cookies, 1)
	require.True(t, cookies[0].Secure)
	require.True(t, cookies[0].HttpOnly)
	require.Equal(t, http.SameSiteStrictMode, cookies[0].SameSite)
	require.Equal(t, cookieName, cookies[0].Name)
	require.Equal(t, "/", cookies[0].Path)
	return cookies[0], data.CSRF
}

func TestSessionAndAuthorization(t *testing.T) {
	s, auth := testServer(t, "admin")
	require.Equal(t, http.StatusUnauthorized, call(s, "GET", "catalog", "", nil, "").Code)
	cookie, csrf := signIn(t, s)
	require.Equal(t, http.StatusOK, call(s, "GET", "session", "", cookie, "").Code)
	require.Equal(t, http.StatusForbidden, call(s, "POST", "logout", "{}", cookie, "wrong").Code)
	require.Equal(t, http.StatusNoContent, call(s, "POST", "logout", "{}", cookie, csrf).Code)
	require.Equal(t, http.StatusUnauthorized, call(s, "GET", "session", "", cookie, "").Code)
	cookie, _ = signIn(t, s)
	key := sessionKey(cookie.Value)
	s.mu.Lock()
	current := s.sessions[key]
	current.Checked = time.Now().Add(-2 * time.Minute)
	s.sessions[key] = current
	s.mu.Unlock()
	auth.denied = true
	require.Equal(t, http.StatusUnauthorized, call(s, "GET", "catalog", "", cookie, "").Code)
	data, err := os.ReadFile(s.config.AuditFile)
	require.NoError(t, err)
	require.Contains(t, string(data), `"result":"revoked"`)
	require.NotContains(t, string(data), auth.password)
	require.NotContains(t, string(data), cookie.Value)
}

func TestManagementIsReadOnlyForEveryGroup(t *testing.T) {
	for _, role := range []string{"reader", "admin"} {
		s, _ := testServer(t, role)
		cookie, csrf := signIn(t, s)
		require.Equal(t, http.StatusOK, call(s, "GET", "catalog", "", cookie, "").Code)
		for _, action := range []string{"revoke", "uploads"} {
			require.Equal(t, http.StatusMethodNotAllowed, call(s, "POST", action, "{}", cookie, csrf).Code)
		}
		for _, directory := range []string{s.config.ExtensionsDir, s.config.IncomingDir} {
			entries, err := os.ReadDir(directory)
			require.NoError(t, err)
			require.Empty(t, entries)
		}
	}
}

func TestCrossSiteAndAmbiguousInput(t *testing.T) {
	s, _ := testServer(t, "admin")
	for _, change := range []func(*http.Request){func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }, func(r *http.Request) { r.Host = "evil.example" }, func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }} {
		req := httptest.NewRequest("POST", s.config.PublicURL+"/admin/api/login", strings.NewReader(`{"username":"alice","password":"test-user-password"}`))
		req.Header.Set("Origin", s.config.PublicURL)
		req.Header.Set("Content-Type", "application/json")
		change(req)
		response := httptest.NewRecorder()
		s.ServeHTTP(response, req)
		require.Equal(t, http.StatusForbidden, response.Code)
		require.Empty(t, response.Header().Get("Access-Control-Allow-Origin"))
	}
	for _, body := range []string{`{"username":"alice","username":"bob","password":"test-user-password"}`, `{"username":"alice","password":"test-user-password","role":"admin"}`} {
		require.Equal(t, http.StatusBadRequest, call(s, "POST", "login", body, nil, "").Code)
	}
	for i := 0; i < 5; i++ {
		require.Equal(t, http.StatusUnauthorized, call(s, "POST", "login", `{"username":"alice","password":"wrong"}`, nil, "").Code)
	}
	require.Equal(t, http.StatusTooManyRequests, call(s, "POST", "login", `{"username":"alice","password":"test-user-password"}`, nil, "").Code)
}

func TestIdleAndAbsoluteExpiration(t *testing.T) {
	for _, idle := range []bool{true, false} {
		s, _ := testServer(t, "admin")
		cookie, _ := signIn(t, s)
		key := sessionKey(cookie.Value)
		s.mu.Lock()
		current := s.sessions[key]
		if idle {
			current.LastSeen = time.Now().Add(-time.Hour)
		} else {
			current.Expires = time.Now().Add(-time.Second)
		}
		s.sessions[key] = current
		s.mu.Unlock()
		require.Equal(t, http.StatusUnauthorized, call(s, "GET", "session", "", cookie, "").Code)
	}
}

func TestConcurrentLogoutDoesNotRestoreSession(t *testing.T) {
	s, _ := testServer(t, "admin")
	cookie, csrf := signIn(t, s)
	var group sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 40; i++ {
		group.Add(1)
		go func() { defer group.Done(); <-start; call(s, "GET", "session", "", cookie, "") }()
	}
	close(start)
	require.Equal(t, http.StatusNoContent, call(s, "POST", "logout", "{}", cookie, csrf).Code)
	group.Wait()
	require.Equal(t, http.StatusUnauthorized, call(s, "GET", "session", "", cookie, "").Code)
}

func TestCatalogAuditFailure(t *testing.T) {
	s, _ := testServer(t, "admin")
	cookie, _ := signIn(t, s)
	extension := testutil.Extensions[0]
	version := storage.Version{Version: extension.LatestVersion}
	vsix := testutil.CreateVSIXFromExtension(t, extension, version)
	manifest, err := storage.ReadVSIXManifest(vsix)
	require.NoError(t, err)
	store, err := storage.NewStorage(context.Background(), &storage.Options{ExtDir: s.config.ExtensionsDir, Logger: slog.Make()})
	require.NoError(t, err)
	_, err = store.AddExtension(context.Background(), manifest, vsix)
	require.NoError(t, err)
	originalAudit := s.config.AuditFile
	s.config.AuditFile = filepath.Join(t.TempDir(), "missing", "audit.jsonl")
	require.Equal(t, http.StatusServiceUnavailable, call(s, "GET", "catalog", "", cookie, "").Code)
	require.DirExists(t, filepath.Join(s.config.ExtensionsDir, extension.Publisher, extension.Name, version.String()))
	s.config.AuditFile = originalAudit
	response := call(s, "GET", "catalog", "", cookie, "")
	require.Equal(t, http.StatusOK, response.Code)
	require.Contains(t, response.Body.String(), extension.Publisher)
}

func TestManagementWithoutIncomingStorage(t *testing.T) {
	config := testConfig(t)
	config.IncomingDir = ""
	require.NoError(t, config.Validate())
	auth := &testAuth{user: User{Name: "alice", DN: "CN=Alice,OU=Users,DC=example", Role: "reader"}, password: "test-user-password"}
	server, err := New(config, auth)
	require.NoError(t, err)
	cookie, _ := signIn(t, server)
	require.Equal(t, http.StatusOK, call(server, "GET", "catalog", "", cookie, "").Code)
}
func TestYAMLConfig(t *testing.T) {
	config := testConfig(t)
	data, err := yaml.Marshal(config)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "admin.yaml")
	require.NoError(t, os.WriteFile(path, data, 0o600))
	loaded, err := LoadConfig(path)
	require.NoError(t, err)
	require.Equal(t, config.Session, loaded.Session)
	for _, extra := range []string{"\nunknown: true\n", "\npublicURL: https://other.example\n", "\n---\npublicURL: https://other.example\n", "\ninvalid: &reference hello\n"} {
		require.NoError(t, os.WriteFile(path, append(data, []byte(extra)...), 0o600))
		_, err := LoadConfig(path)
		require.Error(t, err)
	}
	for _, change := range []func(*Config){func(c *Config) { c.PublicURL = "http://admin.example" }, func(c *Config) { c.LDAP.URL = "http://dc.example" }, func(c *Config) { c.IncomingDir = c.ExtensionsDir }, func(c *Config) { c.LDAP.BindPasswordFile = filepath.Join(c.IncomingDir, "password") }, func(c *Config) { c.Session.RecheckInterval = time.Hour }} {
		invalid := config
		change(&invalid)
		require.Error(t, invalid.Validate())
	}
}

func TestCredentialPathThroughParentSymlink(t *testing.T) {
	config := testConfig(t)
	alias := filepath.Join(t.TempDir(), "storage-alias")
	if err := os.Symlink(filepath.Dir(config.IncomingDir), alias); err != nil {
		t.Skip("directory symlinks unavailable")
	}
	config.LDAP.BindPasswordFile = filepath.Join(alias, "incoming", "not-created-yet")
	require.ErrorContains(t, config.Validate(), "outside package storage")
}
