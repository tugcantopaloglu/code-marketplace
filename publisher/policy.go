package publisher

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/coder/code-marketplace/sandbox"
	"github.com/coder/code-marketplace/storage"
	"github.com/google/uuid"
)

const SigningContext = "code-marketplace/publisher-report/v1\n"
const Marketplace = "https://marketplace.visualstudio.com"

type Identity struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	DisplayName    string `json:"displayName"`
	Domain         string `json:"domain"`
	DomainVerified bool   `json:"isDomainVerified"`
}

type Claims struct {
	SchemaVersion int             `json:"schemaVersion"`
	Source        string          `json:"source"`
	Publisher     Identity        `json:"publisher"`
	Extension     string          `json:"extension"`
	Version       storage.Version `json:"version"`
	SHA256        string          `json:"sha256"`
	SignatureHash string          `json:"signatureSha256"`
	ObservedAt    time.Time       `json:"observedAt"`
	ExpiresAt     time.Time       `json:"expiresAt"`
}

type Approval struct {
	Claims
	KeyID        string `json:"keyId"`
	ReportSHA256 string `json:"reportSha256"`
}

type Policy struct {
	Mode    string
	Keys    map[string]ed25519.PublicKey
	Allowed map[string]bool
	MaxAge  time.Duration
}

func LoadPolicy(path, mode string, maxAge time.Duration) (*Policy, error) {
	if mode != "verified" && mode != "allowlist" && mode != "any" {
		return nil, fmt.Errorf("publisher mode must be verified, allowlist, or any")
	}
	policy := &Policy{Mode: mode, MaxAge: maxAge, Keys: map[string]ed25519.PublicKey{}, Allowed: map[string]bool{}}
	if mode == "any" {
		return policy, nil
	}
	if path == "" || maxAge <= 0 {
		return nil, fmt.Errorf("publisher policy and positive maximum age are required")
	}
	data, err := sandbox.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config struct {
		Keys              map[string]string `json:"keys"`
		AllowedPublishers []string          `json:"allowedPublishers"`
	}
	if err := sandbox.Decode(data, &config); err != nil {
		return nil, err
	}
	for id, encoded := range config.Keys {
		key, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if id == "" || len(id) > 128 || err != nil || len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid publisher attestation key %q", id)
		}
		policy.Keys[id] = key
	}
	if len(policy.Keys) == 0 {
		return nil, fmt.Errorf("publisher policy has no trusted collector keys")
	}
	for _, name := range config.AllowedPublishers {
		if id, ok := strings.CutPrefix(strings.ToLower(name), "id:"); ok {
			parsed, err := uuid.Parse(id)
			if err != nil || parsed == uuid.Nil {
				return nil, fmt.Errorf("invalid allowed Marketplace publisher ID")
			}
			policy.Allowed["id:"+parsed.String()] = true
			continue
		}
		if err := storage.ValidateComponent(name); err != nil {
			return nil, err
		}
		policy.Allowed[strings.ToLower(name)] = true
	}
	if mode == "allowlist" && len(policy.Allowed) == 0 {
		return nil, fmt.Errorf("allowlist mode requires at least one publisher")
	}
	return policy, nil
}

func (p *Policy) Verify(data, vsix, signature []byte, manifest *storage.VSIXManifest, now time.Time) (*Approval, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if p.Mode == "any" {
		return nil, nil
	}
	if manifest == nil {
		return nil, fmt.Errorf("extension manifest is required for publisher verification")
	}
	payload, keyID, err := sandbox.VerifyPayload(data, p.Keys, SigningContext)
	if err != nil {
		return nil, fmt.Errorf("publisher report: %w", err)
	}
	var claims Claims
	if err := sandbox.Decode(payload, &claims); err != nil {
		return nil, err
	}
	identity := manifest.Metadata.Identity
	version := storage.Version{Version: identity.Version, TargetPlatform: identity.TargetPlatform}
	if claims.SchemaVersion != 1 || claims.Source != Marketplace || !strings.EqualFold(claims.Publisher.Name, identity.Publisher) || !strings.EqualFold(claims.Extension, identity.ID) || claims.Version.String() != version.String() {
		return nil, fmt.Errorf("publisher provenance does not match the extension identity")
	}
	publisherID, err := uuid.Parse(claims.Publisher.ID)
	if err != nil || publisherID == uuid.Nil {
		return nil, fmt.Errorf("publisher provenance has no valid Marketplace publisher ID")
	}
	if claims.SHA256 != Hash(vsix) || claims.SignatureHash != Hash(signature) {
		return nil, fmt.Errorf("publisher provenance does not match the package and signature bytes")
	}
	if claims.ObservedAt.IsZero() || claims.ExpiresAt.IsZero() || claims.ObservedAt.After(now) || !claims.ExpiresAt.After(now) || !claims.ExpiresAt.After(claims.ObservedAt) || now.Sub(claims.ObservedAt) > p.MaxAge || claims.ExpiresAt.Sub(claims.ObservedAt) > p.MaxAge {
		return nil, fmt.Errorf("publisher provenance is expired or has invalid observation times")
	}
	if p.Mode == "verified" {
		domain, err := url.Parse(claims.Publisher.Domain)
		if !claims.Publisher.DomainVerified || err != nil || domain.Scheme != "https" || domain.Hostname() == "" || domain.User != nil {
			return nil, fmt.Errorf("marketplace publisher is not verified")
		}
	}
	if len(p.Allowed) > 0 && !p.Allowed[strings.ToLower(claims.Publisher.Name)] && !p.Allowed["id:"+publisherID.String()] {
		return nil, fmt.Errorf("publisher is not on the allowed publisher list")
	}
	return &Approval{Claims: claims, KeyID: keyID, ReportSHA256: Hash(data)}, nil
}

func (p *Policy) Validate() error {
	if p == nil {
		return fmt.Errorf("publisher policy is required")
	}
	if p.Mode == "any" {
		return nil
	}
	if (p.Mode != "verified" && p.Mode != "allowlist") || p.MaxAge <= 0 || len(p.Keys) == 0 {
		return fmt.Errorf("invalid publisher policy")
	}
	if p.Mode == "allowlist" && len(p.Allowed) == 0 {
		return fmt.Errorf("allowlist mode requires at least one publisher")
	}
	return nil
}

func Sign(claims Claims, keyID string, key ed25519.PrivateKey) ([]byte, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	return sandbox.SignPayload(payload, keyID, key, SigningContext)
}

func Hash(data []byte) string { return fmt.Sprintf("%x", sha256.Sum256(data)) }
