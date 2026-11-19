package ingest

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/coder/code-marketplace/publisher"
	"github.com/coder/code-marketplace/storage"
	"github.com/google/uuid"
)

type InternalAutoSign struct {
	Key         ed25519.PrivateKey
	KeyID       string
	UploaderUID uint32
	SkipSandbox bool
}

func (a *InternalAutoSign) validate(policy *publisher.InternalPolicy) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("automatic internal signing requires Linux file ownership")
	}
	if policy == nil || len(a.Key) != ed25519.PrivateKeySize || a.KeyID == "" || a.UploaderUID == 0 || a.UploaderUID == 65534 || a.UploaderUID == ^uint32(0) {
		return fmt.Errorf("automatic internal signing requires an internal policy, a dedicated key and a non-root, non-anonymous uploader UID")
	}
	return nil
}

func (a *InternalAutoSign) authorize(info os.FileInfo, policy *publisher.InternalPolicy, manifest *storage.VSIXManifest) error {
	if !policy.AllowsKey(manifest, a.KeyID, a.Key.Public().(ed25519.PublicKey)) {
		return fmt.Errorf("automatic release key is not authorized for this extension in the internal policy")
	}
	return verifyInternalUploader(info, a.UploaderUID)
}

func (a *InternalAutoSign) sign(input *os.Root, name string, vsix []byte, manifest *storage.VSIXManifest, policy *publisher.InternalPolicy) ([]byte, *publisher.InternalApproval, error) {
	now := time.Now().UTC()
	report, err := publisher.SignInternal(vsix, manifest, a.KeyID, a.Key, now, 24*time.Hour)
	if err != nil {
		return nil, nil, err
	}
	approval, err := policy.Verify(report, vsix, manifest, now)
	if err != nil {
		return nil, nil, err
	}
	temp := ".internal-sign-" + uuid.NewString()
	file, err := input.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if err != nil {
		return nil, nil, err
	}
	defer input.Remove(temp)
	_, err = file.Write(report)
	if err == nil {
		err = file.Sync()
	}
	if err := errors.Join(err, file.Close()); err != nil {
		return nil, nil, err
	}
	if err := input.Link(temp, name); err != nil {
		return nil, nil, fmt.Errorf("publish generated internal report: %w", err)
	}
	return report, approval, nil
}
