package management

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/code-marketplace/publisher"
	"github.com/coder/code-marketplace/sandbox"
)

const cookieName = "__Host-marketplace-admin"

type session struct {
	User     User
	CSRF     string
	Expires  time.Time
	LastSeen time.Time
	Checked  time.Time
}

type window struct {
	Started time.Time
	Count   int
}

type Server struct {
	config     Config
	auth       Authenticator
	mu         sync.Mutex
	auditMu    sync.Mutex
	sessions   map[string]session
	limits     map[string]window
	ldapSlots  chan struct{}
	uploadSlot chan struct{}
	handler    http.Handler
}

func New(config Config, auth Authenticator) (*Server, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if _, err := publisher.LoadPolicy(config.Publisher.PolicyFile, config.Publisher.Mode, config.Publisher.MaxAge); err != nil {
		return nil, err
	}
	if auth == nil {
		var err error
		auth, err = newDirectory(config.LDAP)
		if err != nil {
			return nil, err
		}
	}
	s := &Server{config: config, auth: auth, sessions: map[string]session{}, limits: map[string]window{}, ldapSlots: make(chan struct{}, 8), uploadSlot: make(chan struct{}, 1)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("GET /admin/", s.static)
	mux.HandleFunc("POST /admin/api/login", s.login)
	mux.HandleFunc("POST /admin/api/logout", s.protected(false, "logout", s.logout))
	mux.HandleFunc("GET /admin/api/session", s.protected(false, "session", s.currentSession))
	mux.HandleFunc("GET /admin/api/catalog", s.protected(false, "catalog", s.catalog))
	mux.HandleFunc("GET /admin/api/imports", s.protected(false, "imports", s.imports))
	mux.HandleFunc("GET /admin/api/policy", s.protected(false, "policy", s.policy))
	mux.HandleFunc("POST /admin/api/revoke", s.protected(true, "revoke", s.revoke))
	mux.HandleFunc("POST /admin/api/uploads", s.protected(true, "upload", s.upload))
	s.handler = s.secure(mux)
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.handler.ServeHTTP(w, r) }

func (s *Server) secure(next http.Handler) http.Handler {
	public, _ := url.Parse(s.config.PublicURL)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if r.URL.Path != "/healthz" && !strings.EqualFold(r.Host, public.Host) {
			fail(w, http.StatusForbidden, "Invalid host")
			return
		}
		if strings.HasPrefix(r.URL.Path, "/admin/api/") {
			if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
				fail(w, http.StatusForbidden, "Cross-site request rejected")
				return
			}
			if r.Method != http.MethodGet && r.Header.Get("Origin") != s.config.PublicURL {
				fail(w, http.StatusForbidden, "Invalid request origin")
				return
			}
		}
		if r.Method != http.MethodGet && r.URL.Path != "/admin/api/uploads" {
			if r.Header.Get("Content-Type") != "application/json" {
				fail(w, http.StatusUnsupportedMediaType, "JSON content type required")
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		}
		next.ServeHTTP(w, r)
	})
}

func fail(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(value)
}

func decode(r *http.Request, value any) error {
	data, err := readRequest(r)
	if err != nil {
		return err
	}
	return sandbox.Decode(data, value)
}

func token() string {
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

func sessionKey(value string) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(value))) }

func (s *Server) permit(key string, maxCount int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for name, current := range s.limits {
		if now.Sub(current.Started) >= time.Minute {
			delete(s.limits, name)
		}
	}
	current, ok := s.limits[key]
	if !ok {
		if len(s.limits) >= 4096 {
			return false
		}
		current.Started = now
	}
	if current.Count >= maxCount {
		return false
	}
	current.Count++
	s.limits[key] = current
	return true
}

func (s *Server) authenticate(ctx context.Context, fn func(context.Context) (User, error)) (User, error) {
	select {
	case s.ldapSlots <- struct{}{}:
		defer func() { <-s.ldapSlots }()
	default:
		return User{}, fmt.Errorf("authentication capacity exceeded")
	}
	ctx, cancel := context.WithTimeout(ctx, s.config.LDAP.Timeout)
	defer cancel()
	return fn(ctx)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &credentials); err != nil || len(credentials.Username) > 256 || strings.TrimSpace(credentials.Username) == "" || len(credentials.Password) == 0 || len(credentials.Password) > 4096 {
		fail(w, http.StatusBadRequest, "Invalid credentials")
		return
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	if !s.permit("ip:"+ip, 60) || !s.permit("user:"+sessionKey(strings.ToLower(credentials.Username)), 5) {
		fail(w, http.StatusTooManyRequests, "Login rate limit exceeded")
		return
	}
	user, err := s.authenticate(r.Context(), func(ctx context.Context) (User, error) {
		return s.auth.Authenticate(ctx, credentials.Username, credentials.Password)
	})
	if err != nil {
		if err := s.audit(r, User{Name: credentials.Username}, "login", "", "denied"); err != nil {
			fail(w, http.StatusServiceUnavailable, "Audit storage unavailable")
			return
		}
		fail(w, http.StatusUnauthorized, "Authentication failed")
		return
	}
	if user.Name == "" || user.DN == "" || (user.Role != "reader" && user.Role != "admin") {
		fail(w, http.StatusUnauthorized, "Authentication failed")
		return
	}
	if err := s.audit(r, user, "login", "", "success"); err != nil {
		fail(w, http.StatusServiceUnavailable, "Audit storage unavailable")
		return
	}
	now := time.Now()
	value := session{User: user, CSRF: token(), Expires: now.Add(s.config.Session.Lifetime), LastSeen: now, Checked: now}
	secret := token()
	s.mu.Lock()
	for key, current := range s.sessions {
		if now.After(current.Expires) || now.Sub(current.LastSeen) > s.config.Session.IdleTimeout {
			delete(s.sessions, key)
		}
	}
	if len(s.sessions) >= s.config.Session.MaxSessions {
		s.mu.Unlock()
		fail(w, http.StatusServiceUnavailable, "Session capacity exceeded")
		return
	}
	if previous, err := r.Cookie(cookieName); err == nil {
		delete(s.sessions, sessionKey(previous.Value))
	}
	s.sessions[sessionKey(secret)] = value
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: secret, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: int(s.config.Session.Lifetime.Seconds()), Expires: value.Expires})
	writeJSON(w, http.StatusOK, map[string]any{"user": value.User, "csrfToken": value.CSRF, "expiresAt": value.Expires})
}

type operation func(http.ResponseWriter, *http.Request, session)

func (s *Server) protected(admin bool, action string, next operation) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(cookieName)
		if err != nil || len(cookie.Value) != 43 {
			fail(w, http.StatusUnauthorized, "Sign in required")
			return
		}
		key := sessionKey(cookie.Value)
		s.mu.Lock()
		current, ok := s.sessions[key]
		s.mu.Unlock()
		now := time.Now()
		if !ok || now.After(current.Expires) || now.Sub(current.LastSeen) > s.config.Session.IdleTimeout {
			s.mu.Lock()
			delete(s.sessions, key)
			s.mu.Unlock()
			fail(w, http.StatusUnauthorized, "Session expired")
			return
		}
		if !s.permit("session:"+key, 120) {
			fail(w, http.StatusTooManyRequests, "Request rate limit exceeded")
			return
		}
		if r.Method != http.MethodGet && subtle.ConstantTimeCompare([]byte(current.CSRF), []byte(r.Header.Get("X-CSRF-Token"))) != 1 {
			fail(w, http.StatusForbidden, "Invalid CSRF token")
			return
		}
		if admin || now.Sub(current.Checked) >= s.config.Session.RecheckInterval {
			user, err := s.authenticate(r.Context(), func(ctx context.Context) (User, error) { return s.auth.Authorize(ctx, current.User) })
			if err != nil || user.Name != current.User.Name || user.DN != current.User.DN || (user.Role != "reader" && user.Role != "admin") {
				s.mu.Lock()
				delete(s.sessions, key)
				s.mu.Unlock()
				s.audit(r, current.User, "session", "", "revoked")
				fail(w, http.StatusUnauthorized, "AD authorization unavailable or revoked")
				return
			}
			current.User = user
			current.Checked = now
		}
		if admin && current.User.Role != "admin" {
			s.audit(r, current.User, action, "", "denied")
			fail(w, http.StatusForbidden, "Administrator group required")
			return
		}
		current.LastSeen = now
		s.mu.Lock()
		_, ok = s.sessions[key]
		if ok {
			s.sessions[key] = current
		}
		s.mu.Unlock()
		if !ok {
			fail(w, http.StatusUnauthorized, "Session revoked")
			return
		}
		if !admin && action != "session" {
			if err := s.audit(r, current.User, action, "", "access"); err != nil {
				fail(w, http.StatusServiceUnavailable, "Audit storage unavailable")
				return
			}
		}
		next(w, r, current)
	}
}

func (s *Server) currentSession(w http.ResponseWriter, _ *http.Request, current session) {
	writeJSON(w, http.StatusOK, map[string]any{"user": current.User, "csrfToken": current.CSRF, "expiresAt": current.Expires})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, current session) {
	if err := s.audit(r, current.User, "logout", "", "success"); err != nil {
		fail(w, http.StatusServiceUnavailable, "Audit storage unavailable")
		return
	}
	cookie, _ := r.Cookie(cookieName)
	s.mu.Lock()
	delete(s.sessions, sessionKey(cookie.Value))
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	w.WriteHeader(http.StatusNoContent)
}
