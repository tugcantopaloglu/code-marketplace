package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/code-marketplace/publisher"
	"github.com/coder/code-marketplace/storage"
	"github.com/coder/code-marketplace/testutil"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestCollectionConfig(t *testing.T) {
	for _, tc := range []struct {
		name, data, error string
	}{
		{"selection", "targetPlatform: win32-x64\nextensions:\n  - id: ms-python.python\n  - id: golang.Go\n    version: 0.42.0\n    targetPlatform: linux-x64\n", ""},
		{"unknown field", "extensions:\n  - id: ms-python.python\n    typo: value\n", "field typo"},
		{"duplicate key", "extensions: []\nextensions: []\n", "already defined"},
		{"duplicate entry", "extensions:\n  - id: ms-python.python\n  - id: MS-PYTHON.PYTHON\n", "duplicate extension selection"},
		{"bad platform", "targetPlatform: typo\nextensions:\n  - id: ms-python.python\n", "unsupported target platform"},
		{"bad ID", "extensions:\n  - id: ../../escape\n", "invalid identity"},
		{"missing publisher", "extensions:\n  - id: python\n", "publisher.extension"},
		{"multiple documents", "extensions:\n  - id: ms-python.python\n---\nextensions: []\n", "one collection YAML document"},
		{"anchor", "extensions: &list []\n", "anchors"},
		{"empty", "extensions: []\n", "between 1 and 1000"},
		{"oversized", strings.Repeat(" ", (256<<10)+1), "exceeds 256 KiB"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			filename := filepath.Join(t.TempDir(), "extensions.yaml")
			require.NoError(t, os.WriteFile(filename, []byte(tc.data), 0o600))
			config, err := loadCollectionConfig(filename)
			if tc.error != "" {
				require.ErrorContains(t, err, tc.error)
				return
			}
			require.NoError(t, err)
			require.Equal(t, "verified", config.PublisherMode)
			require.Equal(t, storage.PlatformWin32X64, config.Extensions[0].TargetPlatform)
			require.Equal(t, storage.PlatformLinuxX64, config.Extensions[1].TargetPlatform)
			require.Equal(t, "0.42.0", config.Extensions[1].Version)
		})
	}
}

func collectedTestBundle(t *testing.T, ext testutil.Extension, options publisher.CollectOptions, verified bool) *publisher.Bundle {
	t.Helper()
	vsix := testutil.CreateVSIXFromExtension(t, ext, storage.Version{Version: ext.LatestVersion})
	manifest, err := storage.ReadVSIXManifest(vsix)
	require.NoError(t, err)
	signature := testutil.CreateSignatureArchive(t, vsix)
	now := time.Now().UTC()
	claims := publisher.Claims{SchemaVersion: 1, Source: publisher.Marketplace, Publisher: publisher.Identity{ID: uuid.NewString(), Name: ext.Publisher, Domain: "https://example.com", DomainVerified: verified}, Extension: ext.Name, Version: storage.Version{Version: ext.LatestVersion}, SHA256: publisher.Hash(vsix), SignatureHash: publisher.Hash(signature), ObservedAt: now, ExpiresAt: now.Add(options.Validity)}
	report, err := publisher.Sign(claims, options.KeyID, options.Key)
	require.NoError(t, err)
	return &publisher.Bundle{Manifest: manifest, VSIX: vsix, Signature: signature, Report: report, Claims: claims}
}

func TestCollectionBatchPartialFailureAndUniversalReuse(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	options := publisher.CollectOptions{KeyID: "collector", Key: key, Validity: time.Hour}
	config := &collectionConfig{PublisherMode: "verified"}
	policy, err := config.policy(options)
	require.NoError(t, err)
	first := collectedTestBundle(t, testutil.Extensions[0], options, true)
	unverified := collectedTestBundle(t, testutil.Extensions[1], options, false)
	last := collectedTestBundle(t, testutil.Extensions[2], options, true)
	firstID := first.Claims.Publisher.Name + "." + first.Claims.Extension
	entries := []collectionEntry{{ID: firstID}, {ID: "missing.extension"}, {ID: "unverified.extension"}, {ID: firstID, TargetPlatform: storage.PlatformWin32X64}, {ID: "last.extension"}}
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	require.NoError(t, err)
	defer root.Close()
	progress := &bytes.Buffer{}
	report := runCollectionBatch(context.Background(), entries, options, policy, root, 1, func(_ context.Context, options publisher.CollectOptions) (*publisher.Bundle, error) {
		switch options.Extension {
		case firstID:
			return first, nil
		case "unverified.extension":
			return unverified, nil
		case "last.extension":
			return last, nil
		default:
			return nil, fmt.Errorf("not found")
		}
	}, progress)
	require.Equal(t, 2, report.Collected)
	require.Equal(t, 1, report.Reused)
	require.Equal(t, 2, report.Failed)
	require.Len(t, report.Results, 5)
	require.Contains(t, report.Results[2].Error, "not verified")
	require.Contains(t, progress.String(), "[5/5] last.extension: collected")
	files, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, files, 6)
	for _, file := range files {
		require.False(t, strings.HasSuffix(file.Name(), ".part"))
		require.False(t, strings.HasSuffix(file.Name(), ".sandbox.json"))
	}
	name := storage.ExtensionVSIXNameFromManifest(first.Manifest)
	stored, err := root.ReadFile(name + ".vsix")
	require.NoError(t, err)
	require.Equal(t, first.VSIX, stored)
	stored, err = root.ReadFile(name + ".publisher.json")
	require.NoError(t, err)
	_, err = policy.Verify(stored, first.VSIX, first.Signature, first.Manifest, time.Now().UTC())
	require.NoError(t, err)
}

func TestCollectionPolicyRejectsBlockedOrForgedReports(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	options := publisher.CollectOptions{KeyID: "collector", Key: key, Validity: time.Hour}
	for _, tc := range []struct {
		name, error string
		allowed     []string
		forge       bool
	}{
		{name: "blocked", error: "not on the allowed", allowed: []string{"another-publisher"}},
		{name: "forged", error: "signature", forge: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := &collectionConfig{PublisherMode: "verified", AllowedPublishers: tc.allowed}
			policy, err := config.policy(options)
			require.NoError(t, err)
			bundle := collectedTestBundle(t, testutil.Extensions[0], options, true)
			if tc.forge {
				bundle.Report = bytes.Replace(bundle.Report, []byte(`"signature":"`), []byte(`"signature":"A`), 1)
			}
			dir := t.TempDir()
			root, err := os.OpenRoot(dir)
			require.NoError(t, err)
			defer root.Close()
			report := runCollectionBatch(context.Background(), []collectionEntry{{ID: "selected.extension"}}, options, policy, root, 1, func(context.Context, publisher.CollectOptions) (*publisher.Bundle, error) { return bundle, nil }, io.Discard)
			require.Equal(t, 1, report.Failed)
			require.ErrorContains(t, fmt.Errorf("%s", report.Results[0].Error), tc.error)
			files, err := os.ReadDir(dir)
			require.NoError(t, err)
			require.Empty(t, files)
		})
	}
	for _, config := range []*collectionConfig{
		{PublisherMode: "typo"},
		{PublisherMode: "allowlist"},
		{PublisherMode: "verified", AllowedPublishers: []string{"*"}},
		{PublisherMode: "verified", AllowedPublishers: []string{"id:invalid"}},
		{PublisherMode: "any", AllowedPublishers: []string{"ms-vscode"}},
	} {
		_, err := config.policy(options)
		require.Error(t, err)
	}
}

func TestCollectionBatchCancellationAndRetry(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	options := publisher.CollectOptions{KeyID: "collector", Key: key, Validity: time.Hour}
	policy, err := (&collectionConfig{PublisherMode: "verified"}).policy(options)
	require.NoError(t, err)
	root, err := os.OpenRoot(t.TempDir())
	require.NoError(t, err)
	defer root.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	report := runCollectionBatch(ctx, []collectionEntry{{ID: "first.extension"}, {ID: "next.extension"}}, options, policy, root, 3, func(context.Context, publisher.CollectOptions) (*publisher.Bundle, error) {
		calls++
		cancel()
		return nil, fmt.Errorf("interrupted request")
	}, io.Discard)
	require.Equal(t, 1, calls)
	require.Equal(t, 2, report.Failed)
	require.Contains(t, report.Results[0].Error, "context canceled")
	calls = 0
	bundle := collectedTestBundle(t, testutil.Extensions[0], options, true)
	report = runCollectionBatch(context.Background(), []collectionEntry{{ID: "first.extension"}}, options, policy, root, 2, func(context.Context, publisher.CollectOptions) (*publisher.Bundle, error) {
		calls++
		if calls == 1 {
			return nil, fmt.Errorf("temporary failure")
		}
		return bundle, nil
	}, io.Discard)
	require.Equal(t, 2, calls)
	require.Equal(t, 1, report.Collected)
}

func TestCollectorPreservesExistingFilesAndCleansPartialWrites(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	bundle := collectedTestBundle(t, testutil.Extensions[0], publisher.CollectOptions{KeyID: "collector", Key: key, Validity: time.Hour}, true)
	dir := t.TempDir()
	name := storage.ExtensionVSIXNameFromManifest(bundle.Manifest)
	filename := filepath.Join(dir, name+".publisher.json.part")
	require.NoError(t, os.WriteFile(filename, []byte("existing"), 0o600))
	_, err = openCollectorOutput(dir)
	require.ErrorContains(t, err, "must be empty")
	root, err := os.OpenRoot(dir)
	require.NoError(t, err)
	defer root.Close()
	require.Error(t, writeCollectedBundle(root, bundle))
	files, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, files, 1)
	data, err := os.ReadFile(filename)
	require.NoError(t, err)
	require.Equal(t, "existing", string(data))
}

func TestCollectBatchCommandValidatesBeforeNetwork(t *testing.T) {
	dir := t.TempDir()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	keyPath := filepath.Join(dir, "key.pem")
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600))
	configPath := filepath.Join(dir, "extensions.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte("extensions:\n  - id: ms-vscode.notepadplusplus-keybindings\n"), 0o600))
	output := filepath.Join(dir, "collected")
	require.NoError(t, os.Mkdir(output, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(output, "existing"), []byte("preserved"), 0o600))
	cmd := Root()
	cmd.SetArgs([]string{"collect-batch", "--config", configPath, "--output-dir", output, "--signing-key", keyPath, "--key-id", "collector"})
	require.ErrorContains(t, cmd.Execute(), "must be empty")
}
