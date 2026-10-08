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

	"github.com/coder/code-marketplace/publisher"
	"github.com/coder/code-marketplace/testutil"
	"github.com/stretchr/testify/require"
)

func TestImportSandboxMode(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	bundle := collectedTestBundle(t, testutil.Extensions[0], publisher.CollectOptions{KeyID: "collector", Key: private, Validity: time.Hour}, true)
	input, output := t.TempDir(), t.TempDir()
	root, err := os.OpenRoot(input)
	require.NoError(t, err)
	require.NoError(t, writeCollectedBundle(root, bundle))
	require.NoError(t, root.Close())
	policy := filepath.Join(t.TempDir(), "publisher-policy.json")
	data, err := json.Marshal(map[string]any{"keys": map[string]string{"collector": base64.StdEncoding.EncodeToString(public)}, "allowedPublishers": []string{}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(policy, data, 0o600))
	for _, tc := range []struct {
		name, mode, error string
	}{
		{"default required", "", "--sandbox-trust is required"},
		{"unknown mode", "typo", "--sandbox-mode"},
		{"explicit disabled", "disabled", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := Root()
			args := []string{"import", "--incoming-dir", input, "--extensions-dir", output, "--publisher-policy", policy}
			if tc.mode != "" {
				args = append(args, "--sandbox-mode", tc.mode)
			}
			cmd.SetArgs(args)
			buffer := &bytes.Buffer{}
			cmd.SetOut(buffer)
			err := cmd.Execute()
			if tc.error != "" {
				require.ErrorContains(t, err, tc.error)
			} else {
				require.NoError(t, err)
				require.Contains(t, buffer.String(), `"status":"imported"`)
				require.Contains(t, buffer.String(), `"sandboxMode":"disabled"`)
			}
		})
	}
}

func TestImportReportsPublisherPolicyLoadFailure(t *testing.T) {
	input, output := t.TempDir(), t.TempDir()
	cmd := Root()
	cmd.SetArgs([]string{"import", "--incoming-dir", input, "--extensions-dir", output, "--sandbox-mode", "disabled", "--publisher-policy", filepath.Join(t.TempDir(), "missing.json"), "--write-incoming-report"})
	require.Error(t, cmd.Execute())
	data, err := os.ReadFile(filepath.Join(input, "import-report.json"))
	require.NoError(t, err)
	var report struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	require.NoError(t, json.Unmarshal(data, &report))
	require.Equal(t, "failed", report.Status)
	require.Contains(t, report.Error, "missing.json")
}
