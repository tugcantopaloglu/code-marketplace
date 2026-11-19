package collector

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/coder/code-marketplace/publisher"
	"github.com/coder/code-marketplace/storage"
	"github.com/google/uuid"
)

type Result struct {
	ID       string            `json:"id"`
	Status   string            `json:"status"`
	Reason   string            `json:"reason"`
	Error    string            `json:"error,omitempty"`
	Version  string            `json:"version,omitempty"`
	Verified bool              `json:"verified"`
	Bytes    int64             `json:"bytes,omitempty"`
	Basename string            `json:"basename,omitempty"`
	Claims   *publisher.Claims `json:"claims,omitempty"`
}

type Job struct {
	ID         string     `json:"id"`
	Status     string     `json:"status"`
	Folder     string     `json:"folder"`
	Requested  []string   `json:"requested"`
	Results    []Result   `json:"results"`
	Current    string     `json:"current"`
	Discovered int        `json:"discovered"`
	Completed  int        `json:"completed"`
	Error      string     `json:"error,omitempty"`
	StartedAt  time.Time  `json:"startedAt"`
	FinishedAt *time.Time `json:"finishedAt,omitempty"`
}

type queueItem struct{ id, reason string }

func (s *Server) run(ctx context.Context, job *Job, cancel context.CancelFunc) {
	defer cancel()
	defer func() {
		s.mu.Lock()
		finished := time.Now().UTC()
		job.Current = ""
		copy := clone(job)
		copy.FinishedAt = &finished
		if ctx.Err() != nil {
			copy.Status = "canceled"
		} else if job.Error != "" {
			copy.Status = "failed"
		} else {
			copy.Status = "completed"
			for _, result := range job.Results {
				if result.Status == "failed" || result.Status == "renamed" {
					copy.Status = "partial"
				}
			}
			if copy.Status == "partial" && copy.Completed == 0 {
				copy.Status = "failed"
			}
		}
		s.mu.Unlock()
		// Finalization is part of the job: do not admit a new job until it is done.
		if err := s.export(copy); err != nil {
			copy.Status = "failed"
			copy.Error = "Aktarım raporu yazılamadı: " + err.Error()
			_ = saveJob(copy)
		}
		s.mu.Lock()
		job.Status = copy.Status
		job.Error = copy.Error
		job.FinishedAt = copy.FinishedAt
		delete(s.cancels, job.ID)
		if s.active == job.ID {
			s.active = ""
		}
		s.mu.Unlock()
	}()
	incoming := filepath.Join(job.Folder, "incoming")
	if err := os.Mkdir(incoming, 0o755); err != nil {
		s.mu.Lock()
		job.Error = err.Error()
		s.mu.Unlock()
		return
	}
	queue := []queueItem{}
	seen := map[string]bool{}
	for _, id := range job.Requested {
		queue = append(queue, queueItem{id, "requested"})
		seen[strings.ToLower(id)] = true
	}
	for index := 0; index < len(queue); index++ {
		if ctx.Err() != nil {
			return
		}
		item := queue[index]
		s.mu.Lock()
		job.Current = item.id
		s.mu.Unlock()
		bundle, err := s.collect(ctx, item.id)
		if ctx.Err() != nil {
			return
		}
		result := Result{ID: item.id, Reason: item.reason, Status: "failed"}
		if err == nil {
			err = writeBundle(ctx, incoming, bundle)
		}
		if err != nil {
			result.Error = explainError(err)
			// Known publisher migrations are supplements, never rewritten signed manifests.
			if current := renamed[item.id]; current != "" && strings.Contains(err.Error(), "exactly one extension") {
				result.Status = "renamed"
				result.Error = "Eski kimlik yerine " + current + " eklendi."
				if !seen[strings.ToLower(current)] {
					queue = append(queue, queueItem{current, "replacement:" + item.id})
					seen[strings.ToLower(current)] = true
				}
			}
		} else {
			result.Status = "collected"
			// Keep only the small claims value, not the Bundle that also owns the
			// potentially 512 MiB VSIX buffer, for every item in a long batch.
			claims := bundle.Claims
			result.Claims = &claims
			result.Version = bundle.Claims.Version.Version
			result.Verified = bundle.Claims.Publisher.DomainVerified
			result.Bytes = int64(len(bundle.VSIX))
			result.Basename = storage.ExtensionVSIXNameFromManifest(bundle.Manifest)
			for _, property := range bundle.Manifest.Metadata.Properties.Property {
				kind := ""
				if property.ID == storage.DependencyPropertyType {
					kind = "dependency:"
				}
				if property.ID == storage.PackPropertyType {
					kind = "pack:"
				}
				if kind == "" {
					continue
				}
				for _, dependency := range strings.Split(property.Value, ",") {
					dependency = strings.TrimSpace(dependency)
					if dependency == "" || seen[strings.ToLower(dependency)] {
						continue
					}
					seen[strings.ToLower(dependency)] = true
					if strings.HasPrefix(strings.ToLower(dependency), "vscode.") {
						continue
					}
					if !validID(dependency) {
						result.Error = "Paket geçersiz bir bağımlılık bildiriyor: " + dependency
						result.Status = "failed"
						continue
					}
					if len(queue) >= 250 {
						result.Error = "250 paket sınırına ulaşıldı; bağımlılıklar tamamlanamadı."
						result.Status = "failed"
						continue
					}
					queue = append(queue, queueItem{dependency, kind + item.id})
				}
			}
		}
		s.mu.Lock()
		job.Results = append(job.Results, result)
		job.Discovered = len(queue)
		if result.Claims != nil {
			job.Completed++
		}
		copy := clone(job)
		s.mu.Unlock()
		if err := saveJob(copy); err != nil {
			s.mu.Lock()
			job.Error = "İndirme kaydı yazılamadı: " + err.Error()
			s.mu.Unlock()
			return
		}
	}
}

var renamed = map[string]string{
	"Pivotal.vscode-boot-dev-pack": "vmware.vscode-boot-dev-pack",
	"Pivotal.vscode-concourse":     "vmware.vscode-concourse",
	"Pivotal.vscode-manifest-yaml": "vmware.vscode-manifest-yaml",
	"Pivotal.vscode-spring-boot":   "vmware.vscode-spring-boot",
}

func (s *Server) collect(ctx context.Context, id string) (*publisher.Bundle, error) {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		var bundle *publisher.Bundle
		bundle, err = publisher.Collect(ctx, publisher.CollectOptions{Extension: id, Platform: s.options.Platform,
			KeyID: s.options.KeyID, Key: s.key, Validity: 7 * 24 * time.Hour, Client: s.options.Client})
		if err == nil {
			return bundle, nil
		}
		if ctx.Err() != nil || strings.Contains(err.Error(), "exactly one extension") || strings.Contains(err.Error(), "no matching package") {
			break
		}
		if attempt < 2 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Duration(attempt+1) * time.Second):
			}
		}
	}
	return nil, err
}

func explainError(err error) string {
	text := err.Error()
	switch {
	case strings.Contains(text, "exactly one extension"):
		return "Eklenti Marketplace'de bulunamadı. Kimliği veya güncel yayıncısını kontrol edin."
	case strings.Contains(text, "no matching package"):
		return "Bu platform için kararlı paket bulunamadı."
	case strings.Contains(text, "untrusted"):
		return "Marketplace güvenilmeyen bir indirme adresi döndürdü. Paket kaydedilmedi."
	case strings.Contains(text, "signature"), strings.Contains(text, "digest"), strings.Contains(text, "does not match"):
		return "Paket ve imza doğrulanamadı; paket aktarım klasörüne alınmadı."
	case strings.Contains(text, "status 429"):
		return "Marketplace indirme sınırına ulaşıldı. Bir süre sonra tekrar deneyin."
	default:
		return "İndirme tamamlanamadı: " + text
	}
}

func writeBundle(ctx context.Context, folder string, bundle *publisher.Bundle) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	base := storage.ExtensionVSIXNameFromManifest(bundle.Manifest)
	files := []struct {
		name string
		data []byte
	}{{base + ".sigzip", bundle.Signature}, {base + ".publisher.json", bundle.Report}, {base + ".vsix", bundle.VSIX}}
	for _, file := range files {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := atomicWrite(folder, file.name, file.data, false); err != nil {
			return err
		}
	}
	return nil
}

// atomicWrite stages a complete file next to its destination. In incoming it is
// called with the VSIX last, so partial downloads are never import candidates.
func atomicWrite(folder, name string, data []byte, replace bool) error {
	if !filepath.IsLocal(name) || filepath.Base(name) != name || name == "." {
		return fmt.Errorf("invalid output filename")
	}
	root, err := os.OpenRoot(folder)
	if err != nil {
		return err
	}
	defer root.Close()
	if !replace {
		if _, err := root.Lstat(name); !os.IsNotExist(err) {
			return fmt.Errorf("output file already exists: %s", name)
		}
	}
	tempName := ".collect-" + uuid.NewString() + ".part"
	temporary, err := root.OpenFile(tempName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer root.Remove(tempName)
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if !replace {
		// Publish without a replace race, including on removable Windows disks
		// that do not support hard links.
		err := publishNoReplace(root, temporary, tempName, name)
		closeErr := temporary.Close()
		if err != nil {
			return err
		}
		return closeErr
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return root.Rename(tempName, name)
}

func saveJob(job Job) error {
	data, err := json.MarshalIndent(job, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(job.Folder, "batch-report.json", append(data, '\n'), true)
}

func (s *Server) export(job Job) error {
	if err := saveJob(job); err != nil {
		return err
	}
	policy := struct {
		Keys    map[string]string `json:"keys"`
		Allowed []string          `json:"allowedPublishers"`
	}{Keys: map[string]string{s.options.KeyID: base64.StdEncoding.EncodeToString(s.key.Public().(ed25519.PublicKey))}, Allowed: []string{}}
	publishers := map[string]bool{}
	selection := []string{"targetPlatform: " + string(s.options.Platform), "publisherMode: any", "extensions:"}
	for _, result := range job.Results {
		if result.Claims == nil {
			continue
		}
		claims := result.Claims
		publishers[claims.Publisher.Name] = true
		platform := string(claims.Version.TargetPlatform)
		if platform == "" {
			platform = "universal"
		}
		selection = append(selection, "  - id: "+claims.Publisher.Name+"."+claims.Extension, "    version: \""+claims.Version.Version+"\"", "    targetPlatform: "+platform)
	}
	for name := range publishers {
		policy.Allowed = append(policy.Allowed, name)
	}
	sort.Strings(policy.Allowed)
	data, _ := json.MarshalIndent(policy, "", "  ")
	if err := atomicWrite(job.Folder, "publisher-policy-allowlist.json", append(data, '\n'), true); err != nil {
		return err
	}
	if err := atomicWrite(job.Folder, "extensions.yaml", []byte(strings.Join(selection, "\n")+"\n"), true); err != nil {
		return err
	}
	readme := "Code Marketplace aktarım paketi\n\n" +
		"incoming/ eşleşen VSIX, sigzip ve publisher.json dosyalarını içerir.\n" +
		"Gerekli bağımlılıklar ve paket grubu üyeleri otomatik toplanmıştır.\n" +
		"Eksik veya eski kimlikler için batch-report.json sonucunu kontrol edin.\n" +
		"İmza arşivi ve paket özeti eşleştirildi; bu işlem bir zararlı yazılım taraması değildir.\n" +
		"Publisher gözlemleri indirmeden itibaren 7 gün geçerlidir.\n" +
		"Özel collector anahtarı bu pakette bulunmaz.\n\n" +
		"incoming dosyalarını mevcut offline import akışına aktarın; .sigzip ve .publisher.json\n" +
		"dosyalarını önce, .vsix dosyalarını en son kopyalayın. Importer'ın mevcut publisher\n" +
		"ve sandbox politikaları geçerlidir. Gerekirse public collector anahtarını mevcut\n" +
		"güvenilir policy'ye ekleyin; mevcut anahtarları ve izinleri koruyun.\n"
	if err := atomicWrite(job.Folder, "README.txt", []byte(readme), true); err != nil {
		return err
	}
	checksums := []string{}
	root, err := os.OpenRoot(job.Folder)
	if err != nil {
		return err
	}
	defer root.Close()
	if err := fs.WalkDir(root.FS(), ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if entry.Name() == "SHA256SUMS" || strings.HasSuffix(entry.Name(), ".part") {
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("output contains a non-regular file")
		}
		file, err := root.Open(filepath.FromSlash(path))
		if err != nil {
			return err
		}
		digest := sha256.New()
		_, hashErr := io.Copy(digest, file)
		closeErr := file.Close()
		if hashErr != nil {
			return hashErr
		}
		if closeErr != nil {
			return closeErr
		}
		checksums = append(checksums, fmt.Sprintf("%x  %s", digest.Sum(nil), path))
		return nil
	}); err != nil {
		return err
	}
	sort.Strings(checksums)
	return atomicWrite(job.Folder, "SHA256SUMS", []byte(strings.Join(checksums, "\n")+"\n"), true)
}
