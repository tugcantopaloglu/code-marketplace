package publisher

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/coder/code-marketplace/sandbox"
	"github.com/coder/code-marketplace/storage"
)

const InternalReportSuffix = ".internal.json"
const InternalMaxAge = 7 * 24 * time.Hour
const internalSigningContext = "code-marketplace/internal-release/v1\n"

type InternalClaims struct {
	SchemaVersion int             `json:"schemaVersion"`
	Extension     string          `json:"extension"`
	Version       storage.Version `json:"version"`
	SHA256        string          `json:"sha256"`
	SignedAt      time.Time       `json:"signedAt"`
	ExpiresAt     time.Time       `json:"expiresAt"`
}

type InternalApproval struct {
	InternalClaims
	KeyID        string `json:"keyId"`
	ReportSHA256 string `json:"reportSha256"`
}

type InternalPolicy struct {
	keysByExtension map[string]map[string]ed25519.PublicKey
}

func LoadInternalPolicy(path string) (*InternalPolicy, error) {
	data, err := sandbox.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read internal policy: %w", err)
	}
	var config struct {
		Keys map[string]struct {
			PublicKey  string   `json:"publicKey"`
			Extensions []string `json:"extensions"`
		} `json:"keys"`
	}
	if err := sandbox.Decode(data, &config); err != nil {
		return nil, fmt.Errorf("decode internal policy: %w", err)
	}
	if len(config.Keys) == 0 {
		return nil, fmt.Errorf("internal policy requires at least one release key")
	}
	policy := &InternalPolicy{keysByExtension: map[string]map[string]ed25519.PublicKey{}}
	for keyID, entry := range config.Keys {
		key, err := base64.StdEncoding.Strict().DecodeString(entry.PublicKey)
		if keyID == "" || len(keyID) > 128 || err != nil || len(key) != ed25519.PublicKeySize || len(entry.Extensions) == 0 {
			return nil, fmt.Errorf("invalid internal release key or extension scope for %q", keyID)
		}
		for _, extension := range entry.Extensions {
			publisher, name, ok := strings.Cut(extension, ".")
			if !ok || storage.ValidateComponent(publisher) != nil || storage.ValidateComponent(name) != nil {
				return nil, fmt.Errorf("invalid internal extension ID %q", extension)
			}
			extension = strings.ToLower(extension)
			if policy.keysByExtension[extension] == nil {
				policy.keysByExtension[extension] = map[string]ed25519.PublicKey{}
			}
			policy.keysByExtension[extension][keyID] = ed25519.PublicKey(key)
		}
	}
	return policy, nil
}

func (p *InternalPolicy) Handles(manifest *storage.VSIXManifest) bool {
	return p != nil && len(p.keysByExtension[internalExtensionID(manifest)]) != 0
}

func (p *InternalPolicy) AllowsKey(manifest *storage.VSIXManifest, keyID string, key ed25519.PublicKey) bool {
	return p.Handles(manifest) && len(key) == ed25519.PublicKeySize && bytes.Equal(p.keysByExtension[internalExtensionID(manifest)][keyID], key)
}

func (p *InternalPolicy) Verify(data, vsix []byte, manifest *storage.VSIXManifest, now time.Time) (*InternalApproval, error) {
	if !p.Handles(manifest) {
		return nil, fmt.Errorf("extension is outside the internal policy")
	}
	id := internalExtensionID(manifest)
	payload, keyID, err := sandbox.VerifyPayload(data, p.keysByExtension[id], internalSigningContext)
	if err != nil {
		return nil, fmt.Errorf("internal release report: %w", err)
	}
	var claims InternalClaims
	if err := sandbox.Decode(payload, &claims); err != nil {
		return nil, fmt.Errorf("internal release claims: %w", err)
	}
	identity := manifest.Metadata.Identity
	version := storage.Version{Version: identity.Version, TargetPlatform: identity.TargetPlatform}
	if claims.SchemaVersion != 1 || claims.Extension != id || claims.Version != version || claims.SHA256 != Hash(vsix) {
		return nil, fmt.Errorf("internal release does not match the VSIX identity, version, platform, or SHA-256")
	}
	if claims.SignedAt.IsZero() || claims.SignedAt.After(now) || !claims.ExpiresAt.After(now) || claims.ExpiresAt.Sub(claims.SignedAt) > InternalMaxAge {
		return nil, fmt.Errorf("internal release is expired or has invalid signing times")
	}
	return &InternalApproval{InternalClaims: claims, KeyID: keyID, ReportSHA256: Hash(data)}, nil
}

func SignInternal(vsix []byte, manifest *storage.VSIXManifest, keyID string, key ed25519.PrivateKey, now time.Time, validFor time.Duration) ([]byte, error) {
	if keyID == "" || len(keyID) > 128 || validFor <= 0 || validFor > InternalMaxAge || now.IsZero() || manifest == nil {
		return nil, fmt.Errorf("internal signing requires a manifest, key ID, and validity up to %s", InternalMaxAge)
	}
	identity := manifest.Metadata.Identity
	claims := InternalClaims{
		SchemaVersion: 1,
		Extension:     internalExtensionID(manifest),
		Version:       storage.Version{Version: identity.Version, TargetPlatform: identity.TargetPlatform},
		SHA256:        Hash(vsix),
		SignedAt:      now.UTC(),
		ExpiresAt:     now.Add(validFor).UTC(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	return sandbox.SignPayload(payload, keyID, key, internalSigningContext)
}

func internalExtensionID(manifest *storage.VSIXManifest) string {
	identity := manifest.Metadata.Identity
	return strings.ToLower(storage.ExtensionIDWithoutVersion(identity.Publisher, identity.ID))
}
