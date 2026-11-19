package collector

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/code-marketplace/publisher"
	"github.com/google/uuid"
)

//go:embed web/*
var web embed.FS

type Server struct {
	options     Options
	key         ed25519.PrivateKey
	origin      string
	token       string
	accessToken string
	ctx         context.Context
	mu          sync.Mutex
	jobs        []*Job
	active      string
	closing     bool
	folderBusy  bool
	cancels     map[string]context.CancelFunc
	workers     sync.WaitGroup
	handler     http.Handler
}

// New accepts only a loopback origin; the launcher obtains it from its listener.
func New(ctx context.Context, origin string, options Options) (*Server, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "http" || u.User != nil || (u.Hostname() != "127.0.0.1" && u.Hostname() != "localhost" && u.Hostname() != "::1") || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("collector yalnızca yerel bilgisayarda çalışabilir")
	}
	options, key, err := configure(options)
	if err != nil {
		return nil, err
	}
	random := make([]byte, 64)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	s := &Server{options: options, key: key, origin: origin, token: base64.RawURLEncoding.EncodeToString(random[:32]), accessToken: base64.RawURLEncoding.EncodeToString(random[32:]), ctx: ctx, cancels: map[string]context.CancelFunc{}}
	mux := http.NewServeMux()
	assets, _ := fs.Sub(web, "web")
	mux.Handle("GET /", http.FileServer(http.FS(assets)))
	mux.HandleFunc("GET /api/session", s.session)
	mux.HandleFunc("POST /api/close", s.close)
	mux.HandleFunc("GET /api/search", s.search)
	mux.HandleFunc("POST /api/folder", s.folder)
	mux.HandleFunc("GET /api/jobs", s.list)
	mux.HandleFunc("POST /api/jobs", s.start)
	mux.HandleFunc("GET /api/jobs/{id}", s.get)
	mux.HandleFunc("POST /api/jobs/{id}/cancel", s.cancel)
	mux.HandleFunc("POST /api/jobs/{id}/open", s.open)
	s.handler = s.secure(mux, u.Host)
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.handler.ServeHTTP(w, r) }

// LaunchURL contains a per-launch capability in the fragment, which browsers
// never send in HTTP requests or referrers. It must not be published or logged.
func (s *Server) LaunchURL() string { return s.origin + "/#" + s.accessToken }

func (s *Server) SaveLaunchURL() error {
	return atomicWrite(s.options.DataDir, "current-url.txt", []byte(s.LaunchURL()+"\n"), true)
}

func (s *Server) Wait() {
	s.mu.Lock()
	s.closing = true
	s.mu.Unlock()
	s.workers.Wait()
}

func (s *Server) close(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	active := s.active != ""
	if !active {
		s.closing = true
	}
	s.mu.Unlock()
	if active {
		failure(w, 409, "Önce devam eden indirmeyi durdurun veya bitmesini bekleyin.")
		return
	}
	respond(w, 200, map[string]bool{"closing": true})
	if s.options.OnClose != nil {
		go func() { time.Sleep(200 * time.Millisecond); s.options.OnClose() }()
	}
}

func (s *Server) secure(next http.Handler, host string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		if r.Host != host || r.Header.Get("Sec-Fetch-Site") == "cross-site" || (r.Header.Get("Origin") != "" && r.Header.Get("Origin") != s.origin) {
			failure(w, 403, "Bu arayüze yalnızca yerel adresinden erişilebilir.")
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") && subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+s.accessToken)) != 1 {
			failure(w, 401, "Oturum anahtarı geçersiz. EXE dosyasını yeniden açın ve açılan sayfayı kullanın.")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if r.Header.Get("Origin") != s.origin || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(s.token)) != 1 {
				failure(w, 403, "Oturum doğrulanamadı. Sayfayı yenileyin.")
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
		}
		next.ServeHTTP(w, r)
	})
}

func respond(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func failure(w http.ResponseWriter, status int, message string) {
	respond(w, status, map[string]string{"error": message})
}

func (s *Server) session(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	destination := s.options.Destination
	s.mu.Unlock()
	respond(w, 200, map[string]string{"csrfToken": s.token, "destination": destination, "platform": string(s.options.Platform)})
}

func (s *Server) search(w http.ResponseWriter, r *http.Request) {
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	page := 1
	if raw := r.URL.Query().Get("page"); raw != "" {
		var err error
		page, err = strconv.Atoi(raw)
		if err != nil {
			failure(w, 400, "Sayfa numarası geçersiz.")
			return
		}
	}
	if len(query) < 2 || len(query) > 200 || page < 1 || page > 100 {
		failure(w, 400, "En az 2, en fazla 200 karakterle arayın.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 35*time.Second)
	defer cancel()
	result, err := publisher.Search(ctx, s.options.Client, query, page)
	if err != nil {
		failure(w, 502, "Marketplace'e ulaşılamadı. Bağlantınızı kontrol edip tekrar arayın.")
		return
	}
	respond(w, 200, result)
}

func (s *Server) folder(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if s.folderBusy {
		s.mu.Unlock()
		failure(w, 409, "Klasör seçim penceresi zaten açık.")
		return
	}
	s.folderBusy = true
	initial := s.options.Destination
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.folderBusy = false; s.mu.Unlock() }()
	path, err := chooseFolder(r.Context(), initial)
	if err != nil {
		failure(w, 500, "Klasör penceresi açılamadı. Kayıt yolunu alana yazabilirsiniz.")
		return
	}
	respond(w, 200, map[string]any{"path": path, "canceled": path == ""})
}

func validID(id string) bool {
	publisher, name, ok := strings.Cut(id, ".")
	return ok && !strings.Contains(name, ".") && len(id) <= 256 && validComponent(publisher) && validComponent(name)
}

func validComponent(value string) bool {
	if value == "" || value == "." || value == ".." {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func (s *Server) start(w http.ResponseWriter, r *http.Request) {
	var request struct {
		IDs         []string `json:"ids"`
		Destination string   `json:"destination"`
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		failure(w, 400, "JSON istek gerekli.")
		return
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		failure(w, 400, "Paket seçimi okunamadı.")
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		failure(w, 400, "Tek bir paket seçimi gönderin.")
		return
	}
	if len(request.IDs) == 0 || len(request.IDs) > 100 {
		failure(w, 400, "1–100 eklenti seçin.")
		return
	}
	seen := map[string]bool{}
	ids := []string{}
	for _, id := range request.IDs {
		if !validID(id) {
			failure(w, 400, "Geçersiz eklenti kimliği: "+id)
			return
		}
		if !seen[strings.ToLower(id)] {
			ids = append(ids, id)
			seen[strings.ToLower(id)] = true
		}
	}
	destination := strings.TrimSpace(request.Destination)
	if !filepath.IsAbs(destination) {
		failure(w, 400, "Tam bir kayıt klasörü yolu seçin.")
		return
	}
	s.mu.Lock()
	if s.active != "" || s.closing || s.ctx.Err() != nil {
		s.mu.Unlock()
		failure(w, 409, "Bir indirme sürüyor. Bitmesini bekleyin veya durdurun.")
		return
	}
	// Hold the admission lock through creation so two POSTs cannot start together.
	if err := os.MkdirAll(destination, 0o755); err != nil {
		s.mu.Unlock()
		failure(w, 400, "Kayıt klasörü oluşturulamadı. Yazma izni olan bir klasör seçin.")
		return
	}
	folder, err := os.MkdirTemp(destination, "paket-"+time.Now().Format("20060102-150405")+"-")
	if err != nil {
		s.mu.Unlock()
		failure(w, 400, "Bu klasöre yazılamıyor. Başka bir klasör seçin.")
		return
	}
	ctx, cancel := context.WithCancel(s.ctx)
	job := &Job{ID: uuid.NewString(), Status: "running", Folder: folder, Requested: ids, Results: []Result{}, Discovered: len(ids), StartedAt: time.Now().UTC()}
	s.active = job.ID
	s.cancels[job.ID] = cancel
	s.jobs = append([]*Job{job}, s.jobs...)
	if len(s.jobs) > 20 {
		s.jobs = s.jobs[:20]
	}
	s.options.Destination = destination
	data, _ := json.Marshal(settings{Destination: destination})
	_ = atomicWrite(s.options.DataDir, "settings.json", data, true)
	copy := clone(job)
	s.workers.Add(1)
	s.mu.Unlock()
	go func() { defer s.workers.Done(); s.run(ctx, job, cancel) }()
	respond(w, 202, copy)
}

func clone(job *Job) Job {
	copy := *job
	copy.Requested = append([]string{}, job.Requested...)
	copy.Results = append([]Result{}, job.Results...)
	return copy
}

func (s *Server) find(id string) *Job {
	for _, job := range s.jobs {
		if job.ID == id {
			return job
		}
	}
	return nil
}

func (s *Server) list(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	jobs := []Job{}
	for _, job := range s.jobs {
		jobs = append(jobs, clone(job))
	}
	s.mu.Unlock()
	respond(w, 200, map[string]any{"jobs": jobs})
}

func (s *Server) get(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	job := s.find(r.PathValue("id"))
	if job == nil {
		s.mu.Unlock()
		failure(w, 404, "İndirme bulunamadı.")
		return
	}
	copy := clone(job)
	s.mu.Unlock()
	respond(w, 200, copy)
}

func (s *Server) cancel(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	job := s.find(r.PathValue("id"))
	if job == nil {
		s.mu.Unlock()
		failure(w, 404, "İndirme bulunamadı.")
		return
	}
	if cancel := s.cancels[job.ID]; cancel != nil {
		cancel()
	}
	copy := clone(job)
	s.mu.Unlock()
	respond(w, 200, copy)
}

func (s *Server) open(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	job := s.find(r.PathValue("id"))
	if job == nil {
		s.mu.Unlock()
		failure(w, 404, "İndirme bulunamadı.")
		return
	}
	folder := job.Folder
	s.mu.Unlock()
	if err := openFolder(folder); err != nil {
		failure(w, 500, "Klasör açılamadı. Ekrandaki kayıt yolunu kullanın.")
		return
	}
	respond(w, 200, map[string]bool{"opened": true})
}
