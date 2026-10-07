package publisher_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/coder/code-marketplace/publisher"
	"github.com/coder/code-marketplace/sandbox"
	"github.com/coder/code-marketplace/storage"
	"github.com/coder/code-marketplace/testutil"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestPublisherProvenance(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	vsix := testutil.CreateVSIXFromExtension(t, testutil.Extensions[0], storage.Version{Version: "1.0.0"})
	manifest, err := storage.ReadVSIXManifest(vsix)
	require.NoError(t, err)
	signature := testutil.CreateSignatureArchive(t, vsix)
	now := time.Now().UTC().Truncate(time.Second)
	clean := publisher.Claims{SchemaVersion: 1, Source: publisher.Marketplace, Publisher: publisher.Identity{ID: uuid.NewString(), Name: manifest.Metadata.Identity.Publisher, DisplayName: "Verified publisher", Domain: "https://example.com", DomainVerified: true}, Extension: manifest.Metadata.Identity.ID, Version: storage.Version{Version: "1.0.0"}, SHA256: publisher.Hash(vsix), SignatureHash: publisher.Hash(signature), ObservedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}
	policy := &publisher.Policy{Mode: "verified", Keys: map[string]ed25519.PublicKey{"collector": public}, MaxAge: 24 * time.Hour}
	for _, tc := range []struct {
		name   string
		change func(*publisher.Claims)
	}{
		{"verified", func(*publisher.Claims) {}},
		{"unverified", func(c *publisher.Claims) { c.Publisher.DomainVerified = false }},
		{"publisher spoof", func(c *publisher.Claims) { c.Publisher.Name = "ms-vscode" }},
		{"extension", func(c *publisher.Claims) { c.Extension = "other" }},
		{"platform", func(c *publisher.Claims) { c.Version.TargetPlatform = storage.PlatformLinuxX64 }},
		{"vsix bytes", func(c *publisher.Claims) { c.SHA256 = publisher.Hash([]byte("different VSIX")) }},
		{"signature bytes", func(c *publisher.Claims) { c.SignatureHash = publisher.Hash([]byte("different signature")) }},
		{"source", func(c *publisher.Claims) { c.Source = "https://example.com" }},
		{"publisher GUID", func(c *publisher.Claims) { c.Publisher.ID = "" }},
		{"domain", func(c *publisher.Claims) { c.Publisher.Domain = "http://example.com" }},
		{"expired", func(c *publisher.Claims) { c.ExpiresAt = now }},
		{"future", func(c *publisher.Claims) { c.ObservedAt = now.Add(time.Hour) }},
		{"long validity", func(c *publisher.Claims) { c.ExpiresAt = now.Add(48 * time.Hour) }},
		{"schema", func(c *publisher.Claims) { c.SchemaVersion = 2 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := clean
			tc.change(&claims)
			report, err := publisher.Sign(claims, "collector", private)
			require.NoError(t, err)
			approval, err := policy.Verify(report, vsix, signature, manifest, now)
			if tc.name == "verified" {
				require.NoError(t, err)
				require.True(t, approval.Publisher.DomainVerified)
			} else {
				require.Error(t, err)
			}
		})
	}
	report, err := publisher.Sign(clean, "collector", private)
	require.NoError(t, err)
	_, stranger, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	forged, err := publisher.Sign(clean, "collector", stranger)
	require.NoError(t, err)
	_, err = policy.Verify(forged, vsix, signature, manifest, now)
	require.ErrorContains(t, err, "signature verification")
	policy.Allowed = map[string]bool{"not-the-publisher": true}
	_, err = policy.Verify(report, vsix, signature, manifest, now)
	require.ErrorContains(t, err, "allowed publisher")
	policy.Allowed = map[string]bool{clean.Publisher.Name: true}
	_, err = policy.Verify(report, vsix, signature, manifest, now)
	require.NoError(t, err)
	policy.Allowed = map[string]bool{"id:" + clean.Publisher.ID: true}
	_, err = policy.Verify(report, vsix, signature, manifest, now)
	require.NoError(t, err)
	policy.Allowed = map[string]bool{clean.Publisher.Name: true}
	clean.Publisher.DomainVerified = false
	report, err = publisher.Sign(clean, "collector", private)
	require.NoError(t, err)
	policy.Mode = "allowlist"
	_, err = policy.Verify(report, vsix, signature, manifest, now)
	require.NoError(t, err)
	payload, err := json.Marshal(clean)
	require.NoError(t, err)
	wrongContext, err := sandbox.SignPayload(payload, "collector", private, "code-marketplace/sandbox-report/v1\n")
	require.NoError(t, err)
	_, err = policy.Verify(wrongContext, vsix, signature, manifest, now)
	require.Error(t, err)
}

func TestPublisherModes(t *testing.T) {
	_, err := publisher.LoadPolicy("", "verified", time.Hour)
	require.Error(t, err)
	_, err = publisher.LoadPolicy("", "invalid", time.Hour)
	require.Error(t, err)
	policy, err := publisher.LoadPolicy("", "any", time.Hour)
	require.NoError(t, err)
	approval, err := policy.Verify(nil, nil, nil, nil, time.Now())
	require.NoError(t, err)
	require.Nil(t, approval)
	public, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "policy.json")
	data, err := json.Marshal(map[string]any{"keys": map[string]string{"collector": base64.StdEncoding.EncodeToString(public)}, "allowedPublishers": []string{}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o600))
	_, err = publisher.LoadPolicy(path, "allowlist", time.Hour)
	require.ErrorContains(t, err, "at least one")
	_, err = publisher.LoadPolicy(path, "verified", time.Hour)
	require.NoError(t, err)
}
