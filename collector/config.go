// Package collector implements the connected workstation's local technician UI.
// It is separate from the offline, read-only management service.
package collector

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/coder/code-marketplace/storage"
)

type Options struct {
	DataDir     string
	Destination string
	Platform    storage.Platform
	SigningKey  string
	KeyID       string
	Client      *http.Client
	OnClose     func()
}

type settings struct {
	Destination string `json:"destination"`
}

func configure(options Options) (Options, ed25519.PrivateKey, error) {
	if options.DataDir == "" {
		base, err := os.UserConfigDir()
		if err != nil {
			return options, nil, err
		}
		options.DataDir = filepath.Join(base, "CodeMarketplaceCollector")
	}
	var err error
	options.DataDir, err = filepath.Abs(options.DataDir)
	if err != nil {
		return options, nil, err
	}
	if err := os.MkdirAll(options.DataDir, 0o700); err != nil {
		return options, nil, err
	}
	info, err := os.Lstat(options.DataDir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return options, nil, fmt.Errorf("özel yapılandırma klasörü gerçek bir dizin olmalı")
	}
	if err := protectPrivateDirectory(options.DataDir); err != nil {
		return options, nil, fmt.Errorf("özel yapılandırma klasörü korunamadı: %w", err)
	}
	if options.Destination == "" {
		var saved settings
		data, _ := readPrivateFile(filepath.Join(options.DataDir, "settings.json"))
		_ = json.Unmarshal(data, &saved)
		options.Destination = saved.Destination
		if options.Destination == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return options, nil, err
			}
			options.Destination = filepath.Join(home, "Downloads", "marketplace-paketleri")
		}
	}
	if options.Platform == "" {
		options.Platform = storage.PlatformWin32X64
	}
	if err := storage.ValidateIdentity("publisher", "extension", storage.Version{Version: "1.0.0", TargetPlatform: options.Platform}); err != nil {
		return options, nil, err
	}
	if options.SigningKey == "" {
		options.SigningKey = filepath.Join(options.DataDir, "collector-private.pem")
		if _, err := os.Lstat(options.SigningKey); os.IsNotExist(err) {
			_, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return options, nil, err
			}
			der, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				return options, nil, err
			}
			file, err := os.OpenFile(options.SigningKey, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return options, nil, err
			}
			err = pem.Encode(file, &pem.Block{Type: "PRIVATE KEY", Bytes: der})
			closeErr := file.Close()
			if err != nil || closeErr != nil {
				return options, nil, fmt.Errorf("collector anahtarı kaydedilemedi")
			}
		}
	}
	data, err := readPrivateFile(options.SigningKey)
	if err != nil {
		return options, nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(rest) != 0 {
		return options, nil, fmt.Errorf("collector anahtarı PKCS8 PEM olmalı")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return options, nil, err
	}
	key, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return options, nil, fmt.Errorf("collector anahtarı Ed25519 olmalı")
	}
	if options.KeyID == "" {
		sum := sha256.Sum256(key.Public().(ed25519.PublicKey))
		options.KeyID = "collector-" + hex.EncodeToString(sum[:8])
	}
	if len(options.KeyID) > 128 {
		return options, nil, fmt.Errorf("collector anahtar kimliği çok uzun")
	}
	if options.Client == nil {
		options.Client = &http.Client{Timeout: 4 * time.Minute}
	}
	return options, key, nil
}

func readPrivateFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 64<<10 {
		return nil, fmt.Errorf("özel yapılandırma dosyası geçersiz")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if len(data) > 64<<10 {
		return nil, fmt.Errorf("özel yapılandırma dosyası çok büyük")
	}
	return data, err
}
