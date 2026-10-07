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
	"github.com/coder/code-marketplace/ingest"
	"github.com/coder/code-marketplace/publisher"
	"github.com/coder/code-marketplace/sandbox"
	"github.com/coder/code-marketplace/storage"
	"github.com/coder/code-marketplace/testutil"
	"github.com/stretchr/testify/require"
)

func TestRevokedVersionIsNotReimported(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	input, output := t.TempDir(), t.TempDir()
	ext := testutil.Extensions[0]
	version := storage.Version{Version: ext.LatestVersion}
	vsix := testutil.CreateVSIXFromExtension(t, ext, version)
	require.NoError(t, os.WriteFile(filepath.Join(input, "package.vsix"), vsix, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(input, "package.sigzip"), testutil.CreateSignatureArchive(t, vsix), 0o600))
	now := time.Now().Add(-time.Minute)
	report, err := sandbox.Sign(sandbox.Claims{SchemaVersion: 1, SHA256: fmt.Sprintf("%x", sha256.Sum256(vsix)), Status: "completed", Verdict: "clean", Scanner: "test", ScanID: "test", ScannedAt: now, ExpiresAt: now.Add(time.Hour)}, "test", private)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(input, "package.sandbox.json"), report, 0o600))
	options := ingest.Options{Incoming: input, Storage: output, Policy: &sandbox.Policy{Keys: map[string]ed25519.PublicKey{"test": public}, MaxAge: time.Hour}, PublisherPolicy: &publisher.Policy{Mode: "any"}, Logger: slog.Make()}
	first, err := ingest.Run(context.Background(), options)
	require.NoError(t, err)
	require.Equal(t, "imported", first.Results[0].Status)
	root, err := os.OpenRoot(output)
	require.NoError(t, err)
	defer root.Close()
	require.NoError(t, storage.RevokeVersion(root, storage.Revocation{Publisher: ext.Publisher, Extension: ext.Name, Version: version, Actor: "alice", Reason: "review"}))
	second, err := ingest.Run(context.Background(), options)
	require.NoError(t, err)
	require.Equal(t, "rejected", second.Results[0].Status)
	require.Contains(t, second.Results[0].Reason, "revoked")
	require.NoDirExists(t, filepath.Join(output, ext.Publisher, ext.Name, version.String()))
	data, err := os.ReadFile(filepath.Join(output, ".last-import.json"))
	require.NoError(t, err)
	require.Contains(t, string(data), "revoked")
}
