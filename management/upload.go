package management

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/coder/code-marketplace/extensionsign"
	"github.com/coder/code-marketplace/filelock"
	"github.com/coder/code-marketplace/publisher"
	"github.com/coder/code-marketplace/sandbox"
	"github.com/coder/code-marketplace/storage"
	"github.com/google/uuid"
)

func (s *Server) upload(w http.ResponseWriter, r *http.Request, current session) {
	select {
	case s.uploadSlot <- struct{}{}:
		defer func() { <-s.uploadSlot }()
	default:
		fail(w, http.StatusConflict, "Another upload is running")
		return
	}
	root, err := os.OpenRoot(s.config.IncomingDir)
	if err != nil {
		fail(w, http.StatusServiceUnavailable, "Incoming storage unavailable")
		return
	}
	defer root.Close()
	release, err := filelock.Acquire(root, ".admin-upload.lock")
	if err != nil {
		fail(w, http.StatusConflict, "Another upload is running")
		return
	}
	defer release()
	stage := ".upload-" + uuid.NewString()
	if err := root.Mkdir(stage, 0o700); err != nil {
		fail(w, http.StatusServiceUnavailable, "Upload staging unavailable")
		return
	}
	defer root.RemoveAll(stage)
	r.Body = http.MaxBytesReader(w, r.Body, storage.MaxPackageSize+(34<<20)+(1<<20))
	reader, err := r.MultipartReader()
	if err != nil {
		fail(w, http.StatusBadRequest, "Multipart upload required")
		return
	}
	limits := map[string]int64{"vsix": storage.MaxPackageSize, "signature": 34 << 20, "publisherReport": sandbox.MaxReportSize, "sandboxReport": sandbox.MaxReportSize}
	seen := map[string]bool{}
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			fail(w, http.StatusBadRequest, "Invalid or oversized upload")
			return
		}
		name := part.FormName()
		limit, ok := limits[name]
		if !ok || seen[name] || part.FileName() == "" {
			part.Close()
			fail(w, http.StatusBadRequest, "Invalid or duplicate upload part")
			return
		}
		seen[name] = true
		file, err := root.OpenFile(filepath.Join(stage, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			part.Close()
			fail(w, http.StatusServiceUnavailable, "Upload staging unavailable")
			return
		}
		count, err := io.Copy(file, io.LimitReader(part, limit+1))
		part.Close()
		if err == nil {
			err = file.Sync()
		}
		file.Close()
		if err != nil || count == 0 || count > limit {
			fail(w, http.StatusBadRequest, "Empty, invalid or oversized upload part")
			return
		}
	}
	if !seen["vsix"] || !seen["signature"] {
		fail(w, http.StatusBadRequest, "VSIX and signature are required")
		return
	}
	if s.config.Publisher.Mode != "any" && !seen["publisherReport"] {
		fail(w, http.StatusBadRequest, "Publisher provenance is required")
		return
	}
	vsix, err := storage.ReadPrivateFile(root, filepath.Join(stage, "vsix"), storage.MaxPackageSize)
	if err != nil {
		fail(w, http.StatusBadRequest, "Unable to read uploaded VSIX")
		return
	}
	manifest, err := storage.ReadVSIXManifest(vsix)
	if err != nil {
		fail(w, http.StatusBadRequest, "Invalid VSIX manifest")
		return
	}
	if err := storage.ValidatePackage(manifest, vsix); err != nil {
		fail(w, http.StatusBadRequest, "Invalid VSIX package")
		return
	}
	signature, err := storage.ReadPrivateFile(root, filepath.Join(stage, "signature"), 34<<20)
	if err != nil || extensionsign.ValidateSignatureArchive(vsix, signature) != nil {
		fail(w, http.StatusBadRequest, "Signature does not match the VSIX")
		return
	}
	policy, err := publisher.LoadPolicy(s.config.Publisher.PolicyFile, s.config.Publisher.Mode, s.config.Publisher.MaxAge)
	if err != nil {
		fail(w, http.StatusServiceUnavailable, "Publisher policy unavailable")
		return
	}
	var report []byte
	if seen["publisherReport"] {
		report, err = storage.ReadPrivateFile(root, filepath.Join(stage, "publisherReport"), sandbox.MaxReportSize)
		if err != nil {
			fail(w, http.StatusBadRequest, "Invalid publisher report")
			return
		}
	}
	if _, err := policy.Verify(report, vsix, signature, manifest, time.Now().UTC()); err != nil {
		fail(w, http.StatusBadRequest, "Publisher approval rejected")
		return
	}
	base := storage.ExtensionVSIXNameFromManifest(manifest)
	if filepath.Base(base) != base {
		fail(w, http.StatusBadRequest, "Invalid package basename")
		return
	}
	files := []struct{ part, suffix string }{{"signature", ".sigzip"}, {"publisherReport", ".publisher.json"}, {"sandboxReport", ".sandbox.json"}, {"vsix", ".vsix"}}
	for _, file := range files {
		if seen[file.part] {
			if _, err := root.Lstat(base + file.suffix); !os.IsNotExist(err) {
				fail(w, http.StatusConflict, "Incoming package already exists or is unavailable")
				return
			}
		}
	}
	if err := s.audit(r, current.User, "upload", base, "intent"); err != nil {
		fail(w, http.StatusServiceUnavailable, "Audit storage unavailable")
		return
	}
	for _, file := range files {
		if seen[file.part] {
			if err := root.Rename(filepath.Join(stage, file.part), base+file.suffix); err != nil {
				s.audit(r, current.User, "upload", base, "failed")
				fail(w, http.StatusServiceUnavailable, "Upload publication failed; inspect incoming sidecars")
				return
			}
		}
	}
	if err := s.audit(r, current.User, "upload", base, "success"); err != nil {
		fail(w, http.StatusServiceUnavailable, "Uploaded; final audit write failed")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"file": base + ".vsix", "status": "waiting", "message": fmt.Sprintf("Queued for sandbox and scheduled import: %s", manifest.Metadata.Identity.ID)})
}
