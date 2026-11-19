package ingest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"cdr.dev/slog"
	"github.com/coder/code-marketplace/publisher"
	"github.com/coder/code-marketplace/sandbox"
	"github.com/coder/code-marketplace/storage"
	"github.com/coder/code-marketplace/testutil"
	"github.com/stretchr/testify/require"
)

func TestAutomaticInternalImport(t *testing.T) {
	public, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	scanner, scanKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	extension := testutil.Extensions[0]
	id := storage.ExtensionIDWithoutVersion(extension.Publisher, extension.Name)
	vsix := testutil.CreateVSIXFromExtension(t, extension, storage.Version{Version: "1.0.0"})
	policyPath := filepath.Join(t.TempDir(), "internal-policy.json")
	policyData, err := json.Marshal(map[string]any{"keys": map[string]any{"robot": map[string]any{
		"publicKey": base64.StdEncoding.EncodeToString(public), "extensions": []string{id},
	}}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(policyPath, policyData, 0o600))
	policy, err := publisher.LoadInternalPolicy(policyPath)
	require.NoError(t, err)
	uid := os.Getuid()
	if uid == 0 || uid == 65534 {
		if uid != 0 {
			t.Skip("test cannot select a non-anonymous uploader")
		}
		uid = 12345
	}
	incoming, published := t.TempDir(), t.TempDir()
	options := Options{
		Incoming: incoming, Storage: published, Logger: slog.Make(), SandboxMode: "disabled",
		PublisherPolicy: &publisher.Policy{Mode: "any"},
		Policy:          &sandbox.Policy{Keys: map[string]ed25519.PublicKey{"scanner": scanner}, MaxAge: time.Hour},
		InternalPolicy:  policy,
		InternalAutoSign: &InternalAutoSign{
			Key: key, KeyID: "robot", UploaderUID: uint32(uid),
		},
	}
	const base = "internal-probe"
	path := filepath.Join(incoming, base+".vsix")
	reportPath := filepath.Join(incoming, base+publisher.InternalReportSuffix)
	scanPath := filepath.Join(incoming, base+".sandbox.json")
	require.NoError(t, os.WriteFile(path, vsix, 0o644))
	if os.Getuid() == 0 {
		require.NoError(t, os.Chown(path, uid, -1))
	}
	run := func(status string) Result {
		t.Helper()
		summary, err := Run(t.Context(), options)
		require.NoError(t, err)
		require.Len(t, summary.Results, 1)
		require.Equal(t, status, summary.Results[0].Status, "%s", summary.Results[0].Reason)
		return summary.Results[0]
	}
	require.Contains(t, run("waiting").Reason, ".sandbox.json")
	require.NoFileExists(t, reportPath)

	options.InternalAutoSign.UploaderUID++
	require.Contains(t, run("rejected").Reason, "owned by UID")
	options.InternalAutoSign.UploaderUID--
	require.NoError(t, os.Chmod(path, 0o664))
	require.Contains(t, run("rejected").Reason, "group or other write")
	require.NoError(t, os.Chmod(path, 0o644))
	options.InternalAutoSign.KeyID = "uncertified"
	require.Contains(t, run("rejected").Reason, "not authorized")
	options.InternalAutoSign.KeyID = "robot"

	unprefixed := filepath.Join(incoming, "probe.vsix")
	require.NoError(t, os.Rename(path, unprefixed))
	require.Contains(t, run("waiting").Reason, ".internal.json")
	require.NoError(t, os.Rename(unprefixed, path))
	require.NoError(t, os.WriteFile(scanPath, []byte("{}"), 0o600))
	require.Contains(t, run("rejected").Reason, "sandbox report")
	require.NoFileExists(t, reportPath)
	require.NoError(t, os.WriteFile(reportPath, []byte("{}"), 0o600))
	require.Contains(t, run("rejected").Reason, "internal release report")
	reread, err := os.ReadFile(reportPath)
	require.NoError(t, err)
	require.Equal(t, []byte("{}"), reread)
	require.NoError(t, os.Remove(reportPath))

	scanned := time.Now().UTC().Add(-time.Minute)
	report, err := sandbox.Sign(sandbox.Claims{SchemaVersion: 1, SHA256: publisher.Hash(vsix), Status: "completed", Verdict: "clean",
		Scanner: "test", ScanID: "scan-1", ScannedAt: scanned, ExpiresAt: scanned.Add(time.Hour)}, "scanner", scanKey)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(scanPath, report, 0o600))
	result := run("imported")
	require.Equal(t, "required", result.SandboxMode)
	require.Equal(t, "robot", result.Internal.KeyID)
	generated, err := os.ReadFile(reportPath)
	require.NoError(t, err)
	manifest, err := storage.ReadVSIXManifest(vsix)
	require.NoError(t, err)
	_, err = policy.Verify(generated, vsix, manifest, time.Now().UTC())
	require.NoError(t, err)
	options.Processed = t.TempDir()
	result = run("unchanged")
	require.Equal(t, "archived", result.ArchiveStatus)
	for _, name := range []string{base + ".vsix", base + ".sandbox.json", base + publisher.InternalReportSuffix} {
		require.FileExists(t, filepath.Join(options.Processed, result.ArchivedTo, name))
		require.NoFileExists(t, filepath.Join(incoming, name))
	}
	other := testutil.Extensions[1]
	require.NoError(t, os.WriteFile(path, testutil.CreateVSIXFromExtension(t, other, storage.Version{Version: "1.0.0"}), 0o644))
	require.Contains(t, run("rejected").Reason, "outside the internal policy")
	require.NoFileExists(t, reportPath)

	options.InternalAutoSign.SkipSandbox = true
	sandboxPolicy := options.Policy
	options.Policy = nil
	options.Processed = ""
	require.Contains(t, run("rejected").Reason, "outside the internal policy")

	update := testutil.CreateVSIXFromExtension(t, extension, storage.Version{Version: "1.0.1"})
	require.NoError(t, os.WriteFile(path, update, 0o644))
	if os.Getuid() == 0 {
		require.NoError(t, os.Chown(path, uid, -1))
	}
	result = run("imported")
	require.Equal(t, "disabled", result.SandboxMode)
	require.Equal(t, "robot", result.Internal.KeyID)
	receiptPath := filepath.Join(published, extension.Publisher, extension.Name, "1.0.1", ReceiptName)
	receiptBytes, err := os.ReadFile(receiptPath)
	require.NoError(t, err)
	var receipt Receipt
	require.NoError(t, sandbox.Decode(receiptBytes, &receipt))
	require.Equal(t, "disabled", receipt.SandboxMode)
	require.Nil(t, receipt.Approval)
	require.Equal(t, "disabled", run("unchanged").SandboxMode)

	options.InternalAutoSign.UploaderUID++
	require.Contains(t, run("rejected").Reason, "owned by UID")
	options.InternalAutoSign.UploaderUID--

	manualReportPath := filepath.Join(incoming, "probe"+publisher.InternalReportSuffix)
	require.NoError(t, os.Rename(path, unprefixed))
	require.NoError(t, os.Rename(reportPath, manualReportPath))
	require.Contains(t, run("waiting").Reason, "requires configured sandbox trust")
	require.NoError(t, os.Rename(unprefixed, path))
	require.NoError(t, os.Rename(manualReportPath, reportPath))

	options.InternalAutoSign.SkipSandbox = false
	options.Policy = sandboxPolicy
	require.Contains(t, run("waiting").Reason, ".sandbox.json")
	report, err = sandbox.Sign(sandbox.Claims{SchemaVersion: 1, SHA256: publisher.Hash(update), Status: "completed", Verdict: "clean",
		Scanner: "test", ScanID: "scan-2", ScannedAt: scanned, ExpiresAt: scanned.Add(time.Hour)}, "scanner", scanKey)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(scanPath, report, 0o600))
	require.Contains(t, run("unchanged").Reason, "authenticated sandbox approval")
	receiptBytes, err = os.ReadFile(receiptPath)
	require.NoError(t, err)
	var scannedReceipt Receipt
	require.NoError(t, sandbox.Decode(receiptBytes, &scannedReceipt))
	require.Equal(t, "required", scannedReceipt.SandboxMode)
	require.NotNil(t, scannedReceipt.Approval)
}
