package ingest_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
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

func TestSandboxDisabledRetainsPublisherAndSignatureGates(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	for _, tc := range []struct {
		name, status string
		verified     bool
	}{
		{"accepted", "imported", true},
		{"unverified", "rejected", false},
		{"missing publisher", "waiting", true},
		{"missing signature", "waiting", true},
		{"mismatched signature", "rejected", true},
		{"forged publisher", "rejected", true},
		{"blocked publisher", "rejected", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input, output := t.TempDir(), t.TempDir()
			ext := testutil.Extensions[0]
			vsix := testutil.CreateVSIXFromExtension(t, ext, storage.Version{Version: ext.LatestVersion})
			sig := testutil.CreateSignatureArchive(t, vsix)
			now := time.Now().UTC().Add(-time.Minute)
			provenance, err := publisher.Sign(publisher.Claims{SchemaVersion: 1, Source: publisher.Marketplace, Publisher: publisher.Identity{ID: uuid.NewString(), Name: ext.Publisher, Domain: "https://example.com", DomainVerified: tc.verified}, Extension: ext.Name, Version: storage.Version{Version: ext.LatestVersion}, SHA256: publisher.Hash(vsix), SignatureHash: publisher.Hash(sig), ObservedAt: now, ExpiresAt: now.Add(time.Hour)}, "collector", private)
			require.NoError(t, err)
			if tc.name == "forged publisher" {
				provenance[len(provenance)-5] ^= 1
			}
			if tc.name == "mismatched signature" {
				other := ext
				other.Description += " other package"
				sig = testutil.CreateSignatureArchive(t, testutil.CreateVSIXFromExtension(t, other, storage.Version{Version: ext.LatestVersion}))
			}
			files := map[string][]byte{"package.vsix": vsix, "package.sigzip": sig, "package.publisher.json": provenance}
			if tc.name == "missing publisher" {
				delete(files, "package.publisher.json")
			}
			if tc.name == "missing signature" {
				delete(files, "package.sigzip")
			}
			for name, data := range files {
				require.NoError(t, os.WriteFile(filepath.Join(input, name), data, 0o600))
			}
			policy := &publisher.Policy{Mode: "verified", Keys: map[string]ed25519.PublicKey{"collector": public}, MaxAge: 24 * time.Hour}
			if tc.name == "blocked publisher" {
				policy.Allowed = map[string]bool{"another-publisher": true}
			}
			options := ingest.Options{Incoming: input, Storage: output, SandboxMode: "disabled", PublisherPolicy: policy, Logger: slog.Make()}
			summary, err := ingest.Run(context.Background(), options)
			require.NoError(t, err)
			require.Equal(t, tc.status, summary.Results[0].Status)
			require.Equal(t, "disabled", summary.Results[0].SandboxMode)
			target := filepath.Join(output, ext.Publisher, ext.Name, ext.LatestVersion)
			if tc.status != "imported" {
				require.NoDirExists(t, target)
				return
			}
			data, err := os.ReadFile(filepath.Join(target, ingest.ReceiptName))
			require.NoError(t, err)
			var receipt ingest.Receipt
			require.NoError(t, json.Unmarshal(data, &receipt))
			require.Equal(t, "disabled", receipt.SandboxMode)
			require.Nil(t, receipt.Approval)
			require.NotNil(t, receipt.Publisher)
			require.NoFileExists(t, filepath.Join(target, ".sandbox-report.json"))
			_, err = ingest.Run(context.Background(), ingest.Options{Incoming: input, Storage: output, PublisherPolicy: policy})
			require.ErrorContains(t, err, "mandatory")
			options.SandboxMode = "typo"
			_, err = ingest.Run(context.Background(), options)
			require.ErrorContains(t, err, "sandbox mode")
			scannerPublic, scannerPrivate, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)
			options.SandboxMode, options.Policy = "required", &sandbox.Policy{Keys: map[string]ed25519.PublicKey{"scanner": scannerPublic}, MaxAge: time.Hour}
			summary, err = ingest.Run(context.Background(), options)
			require.NoError(t, err)
			require.Equal(t, "waiting", summary.Results[0].Status)
			scan, err := sandbox.Sign(sandbox.Claims{SchemaVersion: 1, SHA256: publisher.Hash(vsix), Status: "completed", Verdict: "clean", Scanner: "test", ScanID: uuid.NewString(), ScannedAt: now, ExpiresAt: now.Add(time.Hour)}, "scanner", scannerPrivate)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(filepath.Join(input, "package.sandbox.json"), scan, 0o600))
			summary, err = ingest.Run(context.Background(), options)
			require.NoError(t, err)
			require.Equal(t, "unchanged", summary.Results[0].Status)
			require.Contains(t, summary.Results[0].Reason, "authenticated sandbox approval")
			data, err = os.ReadFile(filepath.Join(target, ingest.ReceiptName))
			require.NoError(t, err)
			require.NoError(t, json.Unmarshal(data, &receipt))
			require.Equal(t, "required", receipt.SandboxMode)
			require.NotNil(t, receipt.Approval)
			manifest, err := storage.ReadVSIXManifest(vsix)
			require.NoError(t, err)
			stored, err := os.ReadFile(filepath.Join(target, storage.ExtensionVSIXNameFromManifest(manifest)+".vsix"))
			require.NoError(t, err)
			require.Equal(t, vsix, stored)
		})
	}
}
