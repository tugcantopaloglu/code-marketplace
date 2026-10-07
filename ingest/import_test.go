package ingest_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"cdr.dev/slog"
	"github.com/coder/code-marketplace/filelock"
	"github.com/coder/code-marketplace/ingest"
	"github.com/coder/code-marketplace/publisher"
	"github.com/coder/code-marketplace/sandbox"
	"github.com/coder/code-marketplace/storage"
	"github.com/coder/code-marketplace/testutil"
	"github.com/stretchr/testify/require"
)

func TestOfflineImports(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	input, destination := t.TempDir(), t.TempDir()
	policy := &sandbox.Policy{Keys: map[string]ed25519.PublicKey{"scanner": public}, MaxAge: 24 * time.Hour}
	ext := testutil.Extensions[0]
	vsix := testutil.CreateVSIXFromExtension(t, ext, storage.Version{Version: ext.LatestVersion})
	write := func(name, verdict string, content []byte) {
		require.NoError(t, os.WriteFile(filepath.Join(input, name+".vsix"), content, 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(input, name+".sigzip"), testutil.CreateSignatureArchive(t, content), 0o600))
		now := time.Now().UTC().Add(-time.Minute)
		report, err := sandbox.Sign(sandbox.Claims{SchemaVersion: 1, SHA256: fmt.Sprintf("%x", sha256.Sum256(content)), Status: "completed", Verdict: verdict, Scanner: "test", ScanID: name, ScannedAt: now, ExpiresAt: now.Add(time.Hour)}, "scanner", private)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(input, name+".sandbox.json"), report, 0o600))
	}
	write("accepted", "clean", vsix)
	write("rejected", "malicious", vsix)
	require.NoError(t, os.WriteFile(filepath.Join(input, "waiting.vsix"), vsix, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(input, "incomplete.vsix.part"), vsix, 0o600))
	options := ingest.Options{Incoming: input, Storage: destination, Policy: policy, PublisherPolicy: &publisher.Policy{Mode: "any"}, Logger: slog.Make()}
	first, err := ingest.Run(context.Background(), options)
	require.NoError(t, err)
	require.Len(t, first.Results, 3)
	require.Equal(t, "imported", first.Results[0].Status)
	require.Equal(t, ext.Dependencies, first.Results[0].MissingDependencies)
	require.Equal(t, "rejected", first.Results[1].Status)
	require.Equal(t, "waiting", first.Results[2].Status)
	target := filepath.Join(destination, ext.Publisher, ext.Name, ext.LatestVersion)
	receipt, err := os.ReadFile(filepath.Join(target, ingest.ReceiptName))
	require.NoError(t, err)
	second, err := ingest.Run(context.Background(), options)
	require.NoError(t, err)
	require.Equal(t, "unchanged", second.Results[0].Status)
	after, err := os.ReadFile(filepath.Join(target, ingest.ReceiptName))
	require.NoError(t, err)
	require.Equal(t, receipt, after)
	changed := ext
	changed.Description += " changed"
	write("accepted", "clean", testutil.CreateVSIXFromExtension(t, changed, storage.Version{Version: ext.LatestVersion}))
	third, err := ingest.Run(context.Background(), options)
	require.Error(t, err)
	require.Equal(t, "conflict", third.Results[0].Status)
	after, err = os.ReadFile(filepath.Join(target, ingest.ReceiptName))
	require.NoError(t, err)
	require.Equal(t, receipt, after)
	root, err := os.OpenRoot(destination)
	require.NoError(t, err)
	defer root.Close()
	release, err := filelock.Acquire(root, ".ingest.lock")
	require.NoError(t, err)
	_, err = ingest.Run(context.Background(), options)
	require.ErrorContains(t, err, "another import")
	release()
	release, err = filelock.Acquire(root, ".ingest.lock")
	require.NoError(t, err)
	release()
}

func TestImportRequiresPolicyAndSeparateStorage(t *testing.T) {
	_, err := ingest.Run(context.Background(), ingest.Options{Incoming: t.TempDir(), Storage: t.TempDir()})
	require.ErrorContains(t, err, "mandatory")
	public, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	directory := t.TempDir()
	_, err = ingest.Run(context.Background(), ingest.Options{Incoming: directory, Storage: filepath.Join(directory, "published"), Policy: &sandbox.Policy{Keys: map[string]ed25519.PublicKey{"scanner": public}, MaxAge: time.Hour}, PublisherPolicy: &publisher.Policy{Mode: "any"}})
	require.ErrorContains(t, err, "separate")
}
