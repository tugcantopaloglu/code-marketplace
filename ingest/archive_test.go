package ingest

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
	"github.com/coder/code-marketplace/filelock"
	"github.com/coder/code-marketplace/publisher"
	"github.com/coder/code-marketplace/sandbox"
	"github.com/coder/code-marketplace/storage"
	"github.com/coder/code-marketplace/testutil"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func archiveFixture(t *testing.T) (Options, map[string][]byte) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ext := testutil.Extensions[0]
	vsix := testutil.CreateVSIXFromExtension(t, ext, storage.Version{Version: ext.LatestVersion})
	sig := testutil.CreateSignatureArchive(t, vsix)
	now := time.Now().UTC().Add(-time.Minute)
	provenance, err := publisher.Sign(publisher.Claims{SchemaVersion: 1, Source: publisher.Marketplace, Publisher: publisher.Identity{ID: uuid.NewString(), Name: ext.Publisher, Domain: "https://example.com", DomainVerified: true}, Extension: ext.Name, Version: storage.Version{Version: ext.LatestVersion}, SHA256: publisher.Hash(vsix), SignatureHash: publisher.Hash(sig), ObservedAt: now, ExpiresAt: now.Add(time.Hour)}, "collector", private)
	require.NoError(t, err)
	files := map[string][]byte{"package.vsix": vsix, "package.sigzip": sig, "package.publisher.json": provenance}
	options := Options{Incoming: t.TempDir(), Storage: t.TempDir(), Processed: t.TempDir(), WriteIncomingReport: true, SandboxMode: "disabled", PublisherPolicy: &publisher.Policy{Mode: "verified", Keys: map[string]ed25519.PublicKey{"collector": public}, MaxAge: time.Hour}, Logger: slog.Make()}
	for name, data := range files {
		require.NoError(t, os.WriteFile(filepath.Join(options.Incoming, name), data, 0o600))
	}
	return options, files
}

func TestArchiveAcceptedBundlesAndKeepRejectedInputs(t *testing.T) {
	options, files := archiveFixture(t)
	require.NoError(t, os.WriteFile(filepath.Join(options.Incoming, "rejected.vsix"), []byte("invalid zip"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(options.Incoming, "waiting.vsix"), files["package.vsix"], 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(options.Incoming, "upload.vsix.part"), []byte("incomplete"), 0o600))
	summary, err := Run(context.Background(), options)
	require.NoError(t, err)
	require.Equal(t, "completed", summary.Status)
	require.Len(t, summary.Results, 3)
	require.Equal(t, "imported", summary.Results[0].Status)
	require.Equal(t, "archived", summary.Results[0].ArchiveStatus)
	require.Equal(t, "rejected", summary.Results[1].Status)
	require.Equal(t, "waiting", summary.Results[2].Status)
	archive := filepath.Join(options.Processed, summary.Results[0].ArchivedTo)
	for name, expected := range files {
		require.NoFileExists(t, filepath.Join(options.Incoming, name))
		data, err := os.ReadFile(filepath.Join(archive, name))
		require.NoError(t, err)
		require.Equal(t, expected, data)
	}
	require.FileExists(t, filepath.Join(archive, ".archive-state.json"))
	for _, name := range []string{"rejected.vsix", "waiting.vsix", "upload.vsix.part"} {
		require.FileExists(t, filepath.Join(options.Incoming, name))
	}
	report, err := os.ReadFile(filepath.Join(options.Incoming, IncomingReportName))
	require.NoError(t, err)
	var stored Summary
	require.NoError(t, json.Unmarshal(report, &stored))
	require.Equal(t, summary.Results[0].ArchivedTo, stored.Results[0].ArchivedTo)
	require.Equal(t, "completed", stored.Status)
	second, err := Run(context.Background(), options)
	require.NoError(t, err)
	require.Len(t, second.Results, 2)
	report, err = os.ReadFile(filepath.Join(options.Incoming, IncomingReportName))
	require.NoError(t, err)
	stored = Summary{}
	require.NoError(t, json.Unmarshal(report, &stored))
	require.Equal(t, second.CompletedAt, stored.CompletedAt)
	require.Len(t, stored.Results, 2)
	archives, err := os.ReadDir(options.Processed)
	require.NoError(t, err)
	require.Len(t, archives, 1)
}

func TestArchiveUnchangedAndValidatedSandboxSidecars(t *testing.T) {
	options, files := archiveFixture(t)
	archive := options.Processed
	options.Processed, options.WriteIncomingReport = "", false
	first, err := Run(context.Background(), options)
	require.NoError(t, err)
	require.Equal(t, "imported", first.Results[0].Status)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	now := time.Now().UTC().Add(-time.Minute)
	scan, err := sandbox.Sign(sandbox.Claims{SchemaVersion: 1, SHA256: hash(files["package.vsix"]), Status: "completed", Verdict: "clean", Scanner: "test", ScanID: uuid.NewString(), ScannedAt: now, ExpiresAt: now.Add(time.Hour)}, "scanner", private)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(options.Incoming, "package.sandbox.json"), scan, 0o600))
	files["package.sandbox.json"] = scan
	options.Processed, options.WriteIncomingReport, options.SandboxMode = archive, true, "required"
	options.Policy = &sandbox.Policy{Keys: map[string]ed25519.PublicKey{"scanner": public}, MaxAge: time.Hour}
	second, err := Run(context.Background(), options)
	require.NoError(t, err)
	require.Equal(t, "unchanged", second.Results[0].Status)
	require.Equal(t, "archived", second.Results[0].ArchiveStatus)
	for name, expected := range files {
		data, err := os.ReadFile(filepath.Join(archive, second.Results[0].ArchivedTo, name))
		require.NoError(t, err)
		require.Equal(t, expected, data)
	}
	input, err := os.ReadDir(options.Incoming)
	require.NoError(t, err)
	require.Len(t, input, 1)
	require.Equal(t, IncomingReportName, input[0].Name())
}

func TestArchiveRejectsChangedBytesAndRestoresBundle(t *testing.T) {
	options, files := archiveFixture(t)
	input, err := os.OpenRoot(options.Incoming)
	require.NoError(t, err)
	defer input.Close()
	processed, err := os.OpenRoot(options.Processed)
	require.NoError(t, err)
	defer processed.Close()
	hashes := map[string]string{}
	for name, data := range files {
		hashes[name] = hash(data)
	}
	changed := []byte("replacement report")
	require.NoError(t, os.WriteFile(filepath.Join(options.Incoming, "package.publisher.json"), changed, 0o600))
	_, recovery, err := archivePackage(context.Background(), input, processed, Result{File: "package.vsix", Status: "imported", SHA256: hash(files["package.vsix"]), sourceHashes: hashes})
	require.ErrorContains(t, err, "changed after publication")
	require.Empty(t, recovery)
	for name, original := range files {
		data, err := os.ReadFile(filepath.Join(options.Incoming, name))
		require.NoError(t, err)
		if name == "package.publisher.json" {
			require.Equal(t, changed, data)
		} else {
			require.Equal(t, original, data)
		}
	}
	entries, err := os.ReadDir(options.Incoming)
	require.NoError(t, err)
	require.Len(t, entries, 3)
}

func TestReportConfigurationFailuresAndDoNotClobberActiveRun(t *testing.T) {
	options, files := archiveFixture(t)
	options.Processed = filepath.Join(t.TempDir(), "not-a-directory")
	require.NoError(t, os.WriteFile(options.Processed, []byte("preserved"), 0o600))
	result, err := Run(context.Background(), options)
	require.Error(t, err)
	require.Equal(t, "failed", result.Status)
	data, err := os.ReadFile(filepath.Join(options.Incoming, IncomingReportName))
	require.NoError(t, err)
	var report Summary
	require.NoError(t, json.Unmarshal(data, &report))
	require.NotEmpty(t, report.Error)
	for name := range files {
		require.FileExists(t, filepath.Join(options.Incoming, name))
	}
	output, err := os.OpenRoot(options.Storage)
	require.NoError(t, err)
	defer output.Close()
	release, err := filelock.Acquire(output, ".ingest.lock")
	require.NoError(t, err)
	defer release()
	_, err = Run(context.Background(), options)
	require.ErrorContains(t, err, "another import")
	after, err := os.ReadFile(filepath.Join(options.Incoming, IncomingReportName))
	require.NoError(t, err)
	require.Equal(t, data, after)
}

func TestReportUnfinishedArchiveAndRejectOverlappingStorage(t *testing.T) {
	options, _ := archiveFixture(t)
	recovery := ".archive-" + uuid.NewString()
	require.NoError(t, os.Mkdir(filepath.Join(options.Incoming, recovery), 0o700))
	summary, err := Run(context.Background(), options)
	require.ErrorContains(t, err, "require recovery")
	require.Equal(t, []string{recovery}, summary.RecoveryDirs)
	require.Equal(t, "failed", summary.Status)
	options.Processed = filepath.Join(options.Incoming, "processed")
	_, err = Run(context.Background(), options)
	require.ErrorContains(t, err, "separate directories")
	require.NoDirExists(t, options.Processed)
}
