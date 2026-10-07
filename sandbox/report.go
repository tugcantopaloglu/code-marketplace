package sandbox

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"time"
)

const MaxReportSize = 64 << 10
const signingContext = "code-marketplace/sandbox-report/v1\n"

type Claims struct {
	SchemaVersion int       `json:"schemaVersion"`
	SHA256        string    `json:"sha256"`
	Status        string    `json:"status"`
	Verdict       string    `json:"verdict"`
	Scanner       string    `json:"scanner"`
	ScanID        string    `json:"scanId"`
	ScannedAt     time.Time `json:"scannedAt"`
	ExpiresAt     time.Time `json:"expiresAt"`
}

type Envelope struct {
	KeyID     string `json:"keyId"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type Policy struct {
	Keys   map[string]ed25519.PublicKey
	MaxAge time.Duration
}

type Approval struct {
	Claims
	KeyID        string `json:"keyId"`
	ReportSHA256 string `json:"reportSha256"`
}

func LoadPolicy(path string, maxAge time.Duration) (*Policy, error) {
	if maxAge <= 0 {
		return nil, fmt.Errorf("sandbox maximum report age must be positive")
	}
	data, err := ReadFile(path)
	if err != nil {
		return nil, err
	}
	var config struct {
		Keys map[string]string `json:"keys"`
	}
	if err := Decode(data, &config); err != nil {
		return nil, fmt.Errorf("sandbox trust configuration: %w", err)
	}
	policy := &Policy{Keys: map[string]ed25519.PublicKey{}, MaxAge: maxAge}
	for id, encoded := range config.Keys {
		key, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if id == "" || len(id) > 128 || err != nil || len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid sandbox public key %q", id)
		}
		policy.Keys[id] = ed25519.PublicKey(key)
	}
	if len(policy.Keys) == 0 {
		return nil, fmt.Errorf("sandbox trust configuration has no keys")
	}
	return policy, nil
}

func (p *Policy) Verify(data, vsix []byte, now time.Time) (*Approval, error) {
	if p == nil || p.MaxAge <= 0 {
		return nil, fmt.Errorf("sandbox policy is required")
	}
	payload, keyID, err := VerifyPayload(data, p.Keys, signingContext)
	if err != nil {
		return nil, fmt.Errorf("sandbox report: %w", err)
	}
	var claims Claims
	if err := Decode(payload, &claims); err != nil {
		return nil, fmt.Errorf("sandbox report claims: %w", err)
	}
	if claims.SchemaVersion != 1 || claims.Status != "completed" || claims.Verdict != "clean" {
		return nil, fmt.Errorf("sandbox report does not approve this package")
	}
	if claims.Scanner == "" || len(claims.Scanner) > 256 || claims.ScanID == "" || len(claims.ScanID) > 256 {
		return nil, fmt.Errorf("sandbox report scanner and scanId are required")
	}
	if claims.ScannedAt.IsZero() || claims.ExpiresAt.IsZero() || claims.ScannedAt.After(now) || !claims.ExpiresAt.After(now) || !claims.ExpiresAt.After(claims.ScannedAt) || now.Sub(claims.ScannedAt) > p.MaxAge || claims.ExpiresAt.Sub(claims.ScannedAt) > p.MaxAge {
		return nil, fmt.Errorf("sandbox report is expired or has invalid scan times")
	}
	digest := sha256.Sum256(vsix)
	if claims.SHA256 != hex.EncodeToString(digest[:]) {
		return nil, fmt.Errorf("sandbox report SHA-256 does not match the VSIX")
	}
	reportDigest := sha256.Sum256(data)
	return &Approval{Claims: claims, KeyID: keyID, ReportSHA256: hex.EncodeToString(reportDigest[:])}, nil
}

func Sign(claims Claims, keyID string, key ed25519.PrivateKey) ([]byte, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	return SignPayload(payload, keyID, key, signingContext)
}

func VerifyPayload(data []byte, keys map[string]ed25519.PublicKey, context string) ([]byte, string, error) {
	var envelope Envelope
	if err := Decode(data, &envelope); err != nil {
		return nil, "", err
	}
	key := keys[envelope.KeyID]
	if len(key) != ed25519.PublicKeySize {
		return nil, "", fmt.Errorf("report uses an untrusted key")
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(envelope.Payload)
	if err != nil {
		return nil, "", fmt.Errorf("invalid report payload")
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(key, append([]byte(context), payload...), signature) {
		return nil, "", fmt.Errorf("report signature verification failed")
	}
	return payload, envelope.KeyID, nil
}

func SignPayload(payload []byte, keyID string, key ed25519.PrivateKey, context string) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize || keyID == "" || len(payload) > MaxReportSize {
		return nil, fmt.Errorf("signing key, key ID, and bounded payload are required")
	}
	data, err := json.Marshal(Envelope{
		KeyID: keyID, Payload: base64.StdEncoding.EncodeToString(payload),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, append([]byte(context), payload...))),
	})
	if err != nil {
		return nil, err
	}
	if len(data) > MaxReportSize {
		return nil, fmt.Errorf("signed report exceeds size limit")
	}
	return data, nil
}

func ReadFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("sandbox input must be a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, MaxReportSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxReportSize {
		return nil, fmt.Errorf("sandbox input exceeds size limit")
	}
	return data, nil
}

func Decode(data []byte, value any) error {
	if len(data) > MaxReportSize {
		return fmt.Errorf("JSON exceeds size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := uniqueJSON(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("JSON contains trailing content")
	}
	typeOfValue := reflect.TypeOf(value)
	if typeOfValue == nil || typeOfValue.Kind() != reflect.Pointer || typeOfValue.Elem().Kind() != reflect.Struct {
		return fmt.Errorf("JSON target must be a struct pointer")
	}
	allowed := map[string]bool{}
	for _, field := range reflect.VisibleFields(typeOfValue.Elem()) {
		if name := strings.Split(field.Tag.Get("json"), ",")[0]; name != "" && name != "-" {
			allowed[name] = true
		}
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for name := range fields {
		if !allowed[name] {
			return fmt.Errorf("JSON contains unknown field %q", name)
		}
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(value)
}

func uniqueJSON(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	for decoder.More() {
		if delim == '{' {
			token, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok || seen[key] {
				return fmt.Errorf("JSON contains duplicate or invalid keys")
			}
			seen[key] = true
		}
		if err := uniqueJSON(decoder); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}
