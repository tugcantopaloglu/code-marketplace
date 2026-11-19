//go:build !windows

package collector

import "os"

func protectPrivateDirectory(path string) error { return os.Chmod(path, 0o700) }
