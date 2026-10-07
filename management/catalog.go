package management

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"cdr.dev/slog"
	"github.com/coder/code-marketplace/filelock"
	"github.com/coder/code-marketplace/ingest"
	"github.com/coder/code-marketplace/publisher"
	"github.com/coder/code-marketplace/storage"
)

type CatalogEntry struct {
	Publisher   string          `json:"publisher"`
	Extension   string          `json:"extension"`
	DisplayName string          `json:"displayName"`
	Version     storage.Version `json:"version"`
	Receipt     *ingest.Receipt `json:"receipt,omitempty"`
}

func (s *Server) catalog(w http.ResponseWriter, r *http.Request, _ session) {
	store, err := storage.NewStorage(r.Context(), &storage.Options{ExtDir: s.config.ExtensionsDir, Logger: slog.Make()})
	if err != nil {
		fail(w, http.StatusServiceUnavailable, "Catalog unavailable")
		return
	}
	root, err := os.OpenRoot(s.config.ExtensionsDir)
	if err != nil {
		fail(w, http.StatusServiceUnavailable, "Catalog unavailable")
		return
	}
	defer root.Close()
	entries := []CatalogEntry{}
	err = store.WalkExtensions(r.Context(), func(manifest *storage.VSIXManifest, versions []storage.Version) error {
		identity := manifest.Metadata.Identity
		for _, version := range versions {
			if len(entries) >= 10000 {
				return os.ErrInvalid
			}
			entry := CatalogEntry{Publisher: identity.Publisher, Extension: identity.ID, DisplayName: manifest.Metadata.DisplayName, Version: version}
			if err := storage.ValidateIdentity(entry.Publisher, entry.Extension, version); err != nil {
				return err
			}
			data, err := storage.ReadPrivateFile(root, filepath.Join(entry.Publisher, entry.Extension, version.String(), ingest.ReceiptName), 64<<10)
			if err == nil {
				var receipt ingest.Receipt
				if err := json.Unmarshal(data, &receipt); err != nil {
					return err
				}
				entry.Receipt = &receipt
			} else if !os.IsNotExist(err) {
				return err
			}
			entries = append(entries, entry)
		}
		return nil
	})
	if err != nil {
		fail(w, http.StatusServiceUnavailable, "Catalog metadata unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}

func (s *Server) imports(w http.ResponseWriter, _ *http.Request, _ session) {
	root, err := os.OpenRoot(s.config.ExtensionsDir)
	if err != nil {
		fail(w, http.StatusServiceUnavailable, "Import results unavailable")
		return
	}
	defer root.Close()
	data, err := storage.ReadPrivateFile(root, ".last-import.json", 8<<20)
	if os.IsNotExist(err) {
		writeJSON(w, http.StatusOK, map[string]any{"completedAt": nil, "results": []any{}})
		return
	}
	if err != nil {
		fail(w, http.StatusServiceUnavailable, "Import results unavailable")
		return
	}
	var summary ingest.Summary
	if err := json.Unmarshal(data, &summary); err != nil {
		fail(w, http.StatusServiceUnavailable, "Import results invalid")
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

func (s *Server) policy(w http.ResponseWriter, _ *http.Request, _ session) {
	policy, err := publisher.LoadPolicy(s.config.Publisher.PolicyFile, s.config.Publisher.Mode, s.config.Publisher.MaxAge)
	if err != nil {
		fail(w, http.StatusServiceUnavailable, "Publisher policy unavailable")
		return
	}
	allowed := []string{}
	for name := range policy.Allowed {
		allowed = append(allowed, name)
	}
	sort.Strings(allowed)
	writeJSON(w, http.StatusOK, map[string]any{"mode": policy.Mode, "allowedPublishers": allowed, "maxAge": s.config.Publisher.MaxAge.String(), "signatureRequired": true, "sandboxRequired": true})
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request, current session) {
	var record storage.Revocation
	if err := decode(r, &record); err != nil {
		fail(w, http.StatusBadRequest, "Invalid revocation request")
		return
	}
	if err := storage.ValidateIdentity(record.Publisher, record.Extension, record.Version); err != nil || strings.TrimSpace(record.Reason) == "" || len(record.Reason) > 512 {
		fail(w, http.StatusBadRequest, "Valid package identity and reason required")
		return
	}
	record.Actor = current.User.Name
	target := record.Publisher + "." + record.Extension + "@" + record.Version.String()
	root, err := os.OpenRoot(s.config.ExtensionsDir)
	if err != nil {
		fail(w, http.StatusServiceUnavailable, "Storage unavailable")
		return
	}
	defer root.Close()
	release, err := filelock.Acquire(root, ".ingest.lock")
	if err != nil {
		fail(w, http.StatusConflict, "Import or management operation is running")
		return
	}
	defer release()
	if err := s.audit(r, current.User, "revoke", target, "intent"); err != nil {
		fail(w, http.StatusServiceUnavailable, "Audit storage unavailable")
		return
	}
	if err := storage.RevokeVersion(root, record); err != nil {
		s.audit(r, current.User, "revoke", target, "failed")
		fail(w, http.StatusConflict, "Unable to revoke this version")
		return
	}
	if err := s.audit(r, current.User, "revoke", target, "success"); err != nil {
		fail(w, http.StatusServiceUnavailable, "Version revoked; final audit write failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked", "extension": target})
}
