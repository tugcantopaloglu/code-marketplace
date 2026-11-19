package ingest

import (
	"fmt"
	"os"
	"syscall"
)

func verifyInternalUploader(info os.FileInfo, uid uint32) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uid || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("automatic signing requires a VSIX owned by UID %d without group or other write access", uid)
	}
	return nil
}
