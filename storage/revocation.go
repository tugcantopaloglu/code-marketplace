package storage

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Revocation struct {
	Publisher string    `json:"publisher"`
	Extension string    `json:"extension"`
	Version   Version   `json:"version"`
	Actor     string    `json:"actor"`
	Reason    string    `json:"reason"`
	RevokedAt time.Time `json:"revokedAt"`
}

func revocationName(publisher, name string, version Version) string {
	identity := strings.ToLower(filepath.ToSlash(filepath.Join(publisher, name, version.String())))
	return fmt.Sprintf(".revocation-%x.json", sha256.Sum256([]byte(identity)))
}

func IsRevoked(root *os.Root, publisher, name string, version Version) (bool, error) {
	if err := ValidateIdentity(publisher, name, version); err != nil {
		return false, err
	}
	_, err := root.Stat(revocationName(publisher, name, version))
	if os.IsNotExist(err) {
		return false, nil
	}
	return err == nil, err
}

func RevokeVersion(root *os.Root, record Revocation) error {
	if err := ValidateIdentity(record.Publisher, record.Extension, record.Version); err != nil {
		return err
	}
	if record.Actor == "" || strings.TrimSpace(record.Reason) == "" || len(record.Reason) > 512 {
		return fmt.Errorf("revocation actor and reason are required")
	}
	target := filepath.Join(record.Publisher, record.Extension, record.Version.String())
	info, err := root.Lstat(target)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("published version must be a directory")
	}
	marker := revocationName(record.Publisher, record.Extension, record.Version)
	archive := strings.TrimSuffix(marker, ".json") + ".package"
	if _, err := root.Lstat(archive); !os.IsNotExist(err) {
		return fmt.Errorf("revocation archive already exists or is unavailable")
	}
	record.RevokedAt = time.Now().UTC()
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if err := WritePrivateFile(root, marker, data); err != nil {
		return err
	}
	return root.Rename(target, archive)
}

func WritePrivateFile(root *os.Root, name string, data []byte) error {
	if filepath.Base(name) != name || !strings.HasPrefix(name, ".") {
		return fmt.Errorf("private metadata requires a hidden basename")
	}
	staging := ".metadata-" + uuid.NewString()
	file, err := root.OpenFile(staging, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer root.Remove(staging)
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return root.Rename(staging, name)
}

func ReadPrivateFile(root *os.Root, name string, limit int64) ([]byte, error) {
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("metadata must be a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("metadata exceeds its size limit")
	}
	return data, nil
}
