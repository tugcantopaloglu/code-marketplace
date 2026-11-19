package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
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
	"github.com/stretchr/testify/require"
)

func TestInternalReleaseCLI(t *testing.T) {
	run := func(args ...string) (*bytes.Buffer, error) {
		cmd, out := Root(), new(bytes.Buffer)
		cmd.SetOut(out)
		cmd.SetErr(out)
		cmd.SetArgs(args)
		return out, cmd.Execute()
	}
	input, published, keys, processed := t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir()
	ext := testutil.Extensions[0]
	ext.Properties = append(ext.Properties, storage.VSIXProperty{ID: storage.PrivateMarketplaceProperty, Value: "false"})
	ext.Files = append(ext.Files, storage.VSIXAsset{Type: storage.VSIXSignatureType, Path: "icon.png", Addressable: "true"})
	ext.Files = append(ext.Files, storage.VSIXAsset{Type: storage.VSIXAssetType, Path: "icon.png", Addressable: "true"})
	version := storage.Version{Version: "1.0.0", TargetPlatform: storage.PlatformWin32X64}
	internal := testutil.CreateVSIXFromExtension(t, ext, version)
	id := storage.ExtensionIDWithoutVersion(ext.Publisher, ext.Name)
	_, err := run("internal", "keygen", id, "--key-id", "release", "--output-dir", keys)
	require.NoError(t, err)
	privateKey := filepath.Join(keys, "internal-private.pem")
	policyFile := filepath.Join(keys, "internal-policy.json")
	trusted, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	trust, err := json.Marshal(map[string]any{"keys": map[string]string{"scanner": base64.StdEncoding.EncodeToString(trusted)}})
	require.NoError(t, err)
	trustFile := filepath.Join(keys, "sandbox-trust.json")
	require.NoError(t, os.WriteFile(trustFile, trust, 0o600))
	importArgs := []string{"import", "--incoming-dir", input, "--extensions-dir", published, "--internal-policy", policyFile, "--sandbox-mode", "disabled", "--publisher-mode", "any"}
	_, err = run(importArgs...)
	require.ErrorContains(t, err, "--sandbox-trust is required")
	importArgs = append(importArgs, "--sandbox-trust", trustFile)
	importResult := func(extra ...string) ingest.Result {
		t.Helper()
		output, err := run(append(append([]string{}, importArgs...), extra...)...)
		require.NoError(t, err)
		var summary ingest.Summary
		require.NoError(t, json.Unmarshal(output.Bytes(), &summary))
		require.Len(t, summary.Results, 1)
		return summary.Results[0]
	}
	vsixPath := filepath.Join(input, "package.vsix")
	require.NoError(t, os.WriteFile(vsixPath, internal, 0o600))
	require.Contains(t, importResult().Reason, "package.internal.json")
	signArgs := []string{"internal", "sign", vsixPath, "--key-id", "release", "--signing-key", privateKey}
	_, err = run(signArgs...)
	require.NoError(t, err)
	approvalPath := filepath.Join(input, "package.internal.json")
	approval, err := os.ReadFile(approvalPath)
	require.NoError(t, err)
	require.Contains(t, importResult().Reason, "package.sandbox.json")

	modified := ext
	modified.Description = "different package bytes"
	require.NoError(t, os.WriteFile(vsixPath, testutil.CreateVSIXFromExtension(t, modified, version), 0o600))
	require.Contains(t, importResult().Reason, "SHA-256")
	require.NoError(t, os.WriteFile(vsixPath, internal, 0o600))
	policy, err := publisher.LoadInternalPolicy(policyFile)
	require.NoError(t, err)
	manifest, err := storage.ReadVSIXManifest(internal)
	require.NoError(t, err)
	_, err = policy.Verify(approval, internal, manifest, time.Now().Add(publisher.InternalMaxAge))
	require.ErrorContains(t, err, "expired")

	scanTime := time.Now().UTC().Add(-time.Minute)
	scan, err := sandbox.Sign(sandbox.Claims{
		SchemaVersion: 1, SHA256: publisher.Hash(internal), Status: "completed", Verdict: "clean",
		Scanner: "test", ScanID: "scan-1", ScannedAt: scanTime, ExpiresAt: scanTime.Add(time.Hour),
	}, "scanner", private)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(input, "package.sandbox.json"), scan, 0o600))
	result := importResult()
	require.Equal(t, "imported", result.Status)
	require.Equal(t, "required", result.SandboxMode)
	require.NotNil(t, result.Internal)
	require.Nil(t, result.Publisher)

	store, err := storage.NewStorage(t.Context(), &storage.Options{ExtDir: published, Logger: slog.Make(), IncludeEmptySignatures: true})
	require.NoError(t, err)
	marketplaceManifest, err := store.Manifest(t.Context(), ext.Publisher, ext.Name, version)
	require.NoError(t, err)
	require.Equal(t, storage.VSIXProperty{ID: storage.PrivateMarketplaceProperty, Value: "true"}, marketplaceManifest.Metadata.Properties.Property[len(marketplaceManifest.Metadata.Properties.Property)-1])
	servedName := storage.ExtensionVSIXNameFromManifest(manifest) + ".vsix"
	for _, asset := range marketplaceManifest.Assets.Asset {
		require.NotEqual(t, storage.VSIXSignatureType, asset.Type)
		if asset.Type == storage.VSIXAssetType {
			require.Equal(t, servedName, asset.Path)
		}
	}
	stored, err := os.ReadFile(filepath.Join(published, ext.Publisher, ext.Name, version.String(), servedName))
	require.NoError(t, err)
	require.Equal(t, internal, stored)
	result = importResult("--processed-dir", processed)
	require.Equal(t, "unchanged", result.Status)
	require.Equal(t, "archived", result.ArchiveStatus)
	for _, name := range []string{"package.vsix", "package.internal.json", "package.sandbox.json"} {
		require.FileExists(t, filepath.Join(processed, result.ArchivedTo, name))
		require.NoFileExists(t, filepath.Join(input, name))
	}

	other := testutil.Extensions[1]
	other.Properties = append(other.Properties, storage.VSIXProperty{ID: storage.PrivateMarketplaceProperty, Value: "true"})
	require.NoError(t, os.WriteFile(vsixPath, testutil.CreateVSIXFromExtension(t, other, version), 0o600))
	_, err = run(signArgs...)
	require.NoError(t, err)
	require.Contains(t, importResult().Reason, "package.sigzip")
}
