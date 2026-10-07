package cli_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/coder/code-marketplace/cli"
	"github.com/coder/code-marketplace/sandbox"
	"github.com/coder/code-marketplace/storage"
	"github.com/coder/code-marketplace/testutil"
	"github.com/stretchr/testify/require"
)

func TestSandboxGate(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	for _, verdict := range []string{"clean", "malicious", "missing", "forged", "wrong-hash"} {
		t.Run(verdict, func(t *testing.T) {
			input, destination := t.TempDir(), t.TempDir()
			ext := testutil.Extensions[0]
			vsix := testutil.CreateVSIXFromExtension(t, ext, storage.Version{Version: ext.LatestVersion})
			require.NoError(t, os.WriteFile(filepath.Join(input, "package.vsix"), vsix, 0o600))
			require.NoError(t, os.WriteFile(filepath.Join(input, "package.sigzip"), testutil.CreateSignatureArchive(t, vsix), 0o600))
			trust, err := json.Marshal(map[string]any{"keys": map[string]string{"sandbox": base64.StdEncoding.EncodeToString(public)}})
			require.NoError(t, err)
			trustPath := filepath.Join(t.TempDir(), "trust.json")
			require.NoError(t, os.WriteFile(trustPath, trust, 0o600))
			now := time.Now().UTC().Add(-time.Minute)
			claims := sandbox.Claims{SchemaVersion: 1, SHA256: fmt.Sprintf("%x", sha256.Sum256(vsix)), Status: "completed", Verdict: "clean", Scanner: "test", ScanID: "scan-123", ScannedAt: now, ExpiresAt: now.Add(time.Hour)}
			if verdict == "malicious" {
				claims.Verdict = verdict
			}
			if verdict == "wrong-hash" {
				claims.SHA256 = "wrong"
			}
			report, err := sandbox.Sign(claims, "sandbox", private)
			require.NoError(t, err)
			if verdict == "forged" {
				report = bytes.Replace(report, []byte(`"signature":"`), []byte(`"signature":"X`), 1)
			}
			if verdict != "missing" {
				require.NoError(t, os.WriteFile(filepath.Join(input, "package.sandbox.json"), report, 0o600))
			}
			cmd := cli.Root()
			cmd.SetArgs([]string{"add", input, "--require-signature", "--require-sandbox-report", "--sandbox-trust", trustPath, "--extensions-dir", destination})
			cmd.SetOut(new(bytes.Buffer))
			err = cmd.Execute()
			if verdict == "clean" {
				require.NoError(t, err)
				require.FileExists(t, filepath.Join(destination, ext.Publisher, ext.Name, ext.LatestVersion, "extension.vsixmanifest"))
			} else {
				require.Error(t, err)
				entries, err := os.ReadDir(destination)
				require.NoError(t, err)
				require.Empty(t, entries)
			}
		})
	}
}
