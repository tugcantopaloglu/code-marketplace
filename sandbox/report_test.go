package sandbox_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/coder/code-marketplace/sandbox"
	"github.com/stretchr/testify/require"
)

func TestReportPolicy(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	vsix := []byte("approved package")
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	policy := &sandbox.Policy{Keys: map[string]ed25519.PublicKey{"scanner": public}, MaxAge: time.Hour}
	clean := sandbox.Claims{SchemaVersion: 1, SHA256: fmt.Sprintf("%x", sha256.Sum256(vsix)), Status: "completed", Verdict: "clean", Scanner: "test", ScanID: "123", ScannedAt: now.Add(-time.Minute), ExpiresAt: now.Add(30 * time.Minute)}
	for _, tc := range []struct {
		name   string
		change func(*sandbox.Claims)
	}{
		{"clean", func(*sandbox.Claims) {}},
		{"malicious", func(c *sandbox.Claims) { c.Verdict = "malicious" }},
		{"unknown", func(c *sandbox.Claims) { c.Verdict = "unknown" }},
		{"pending", func(c *sandbox.Claims) { c.Status = "pending" }},
		{"hash", func(c *sandbox.Claims) { c.SHA256 = "wrong" }},
		{"expired", func(c *sandbox.Claims) { c.ExpiresAt = now }},
		{"future", func(c *sandbox.Claims) { c.ScannedAt = now.Add(time.Second) }},
		{"stale", func(c *sandbox.Claims) { c.ScannedAt = now.Add(-2 * time.Hour) }},
		{"long validity", func(c *sandbox.Claims) { c.ExpiresAt = now.Add(2 * time.Hour) }},
		{"schema", func(c *sandbox.Claims) { c.SchemaVersion = 2 }},
		{"identity", func(c *sandbox.Claims) { c.ScanID = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := clean
			tc.change(&claims)
			report, err := sandbox.Sign(claims, "scanner", private)
			require.NoError(t, err)
			approval, err := policy.Verify(report, vsix, now)
			if tc.name == "clean" {
				require.NoError(t, err)
				require.Equal(t, "123", approval.ScanID)
			} else {
				require.Error(t, err)
			}
		})
	}
	_, stranger, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	for _, tc := range []struct {
		id  string
		key ed25519.PrivateKey
	}{
		{"unknown", private}, {"scanner", stranger},
	} {
		report, err := sandbox.Sign(clean, tc.id, tc.key)
		require.NoError(t, err)
		_, err = policy.Verify(report, vsix, now)
		require.Error(t, err)
	}
	_, err = policy.Verify([]byte(fmt.Sprintf(`{"keyId":"scanner","payload":"%s","signature":"%s"}`, base64.StdEncoding.EncodeToString([]byte("{}")), base64.StdEncoding.EncodeToString(make([]byte, 64)))), vsix, now)
	require.Error(t, err)
}

func TestStrictJSON(t *testing.T) {
	for _, input := range []string{`{"keyId":"a","keyId":"b"}`, `{"keyId":"a","KEYID":"b"}`, `{"KEYID":"a"}`, `{"unexpected":1}`, `{} {}`, `{"payload":`, `null`, `[]`} {
		var envelope sandbox.Envelope
		err := sandbox.Decode([]byte(input), &envelope)
		if input == "null" {
			_, err = (&sandbox.Policy{MaxAge: time.Hour}).Verify([]byte(input), []byte("package"), time.Now())
		}
		require.Error(t, err, input)
	}
}
