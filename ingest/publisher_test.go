package ingest_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"cdr.dev/slog"
	"github.com/coder/code-marketplace/ingest"
	"github.com/coder/code-marketplace/publisher"
	"github.com/coder/code-marketplace/sandbox"
	"github.com/coder/code-marketplace/storage"
	"github.com/coder/code-marketplace/testutil"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestVerifiedPublisherImportGate(t *testing.T) {
	scannerPublic, scannerPrivate, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	collectorPublic, collectorPrivate, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	for _, tc := range []struct {
		name, mode, status string
		verified           bool
		allowed            map[string]bool
	}{
		{"verified", "verified", "imported", true, nil},
		{"unverified", "verified", "rejected", false, nil},
		{"missing", "verified", "waiting", true, nil},
		{"allowlisted", "verified", "imported", true, map[string]bool{"foo": true}},
		{"not allowlisted", "verified", "rejected", true, map[string]bool{"ms-vscode": true}},
		{"explicit allowlist mode", "allowlist", "imported", false, map[string]bool{"foo": true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input, destination := t.TempDir(), t.TempDir()
			ext := testutil.Extensions[0]
			vsix := testutil.CreateVSIXFromExtension(t, ext, storage.Version{Version: ext.LatestVersion})
			sig := testutil.CreateSignatureArchive(t, vsix)
			now := time.Now().UTC().Add(-time.Minute)
			sandboxReport, err := sandbox.Sign(sandbox.Claims{SchemaVersion: 1, SHA256: publisher.Hash(vsix), Status: "completed", Verdict: "clean", Scanner: "test", ScanID: uuid.NewString(), ScannedAt: now, ExpiresAt: now.Add(time.Hour)}, "scanner", scannerPrivate)
			require.NoError(t, err)
			provenance, err := publisher.Sign(publisher.Claims{SchemaVersion: 1, Source: publisher.Marketplace, Publisher: publisher.Identity{ID: uuid.NewString(), Name: ext.Publisher, Domain: "https://example.com", DomainVerified: tc.verified}, Extension: ext.Name, Version: storage.Version{Version: ext.LatestVersion}, SHA256: publisher.Hash(vsix), SignatureHash: publisher.Hash(sig), ObservedAt: now, ExpiresAt: now.Add(time.Hour)}, "collector", collectorPrivate)
			require.NoError(t, err)
			for name, data := range map[string][]byte{"package.vsix": vsix, "package.sigzip": sig, "package.sandbox.json": sandboxReport} {
				require.NoError(t, os.WriteFile(filepath.Join(input, name), data, 0o600))
			}
			if tc.name != "missing" {
				require.NoError(t, os.WriteFile(filepath.Join(input, "package.publisher.json"), provenance, 0o600))
			}
			result, err := ingest.Run(context.Background(), ingest.Options{Incoming: input, Storage: destination, Logger: slog.Make(), Policy: &sandbox.Policy{Keys: map[string]ed25519.PublicKey{"scanner": scannerPublic}, MaxAge: 24 * time.Hour}, PublisherPolicy: &publisher.Policy{Mode: tc.mode, Allowed: tc.allowed, Keys: map[string]ed25519.PublicKey{"collector": collectorPublic}, MaxAge: 24 * time.Hour}})
			require.NoError(t, err)
			require.Len(t, result.Results, 1)
			require.Equal(t, tc.status, result.Results[0].Status)
			target := filepath.Join(destination, ext.Publisher, ext.Name, ext.LatestVersion, "extension.vsixmanifest")
			if tc.status == "imported" {
				require.FileExists(t, target)
			} else {
				require.NoFileExists(t, target)
			}
		})
	}
}
