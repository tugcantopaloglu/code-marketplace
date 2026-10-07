package filelock_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/coder/code-marketplace/filelock"
	"github.com/stretchr/testify/require"
)

func TestLockReleasedAfterProcessExit(t *testing.T) {
	if directory := os.Getenv("MARKETPLACE_LOCK_HELPER"); directory != "" {
		root, err := os.OpenRoot(directory)
		if err != nil {
			os.Exit(2)
		}
		_, err = filelock.Acquire(root, ".lock")
		if err != nil {
			os.Exit(3)
		}
		if err := os.WriteFile(filepath.Join(directory, "ready"), nil, 0o600); err != nil {
			os.Exit(4)
		}
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
	directory := t.TempDir()
	command := exec.Command(os.Args[0], "-test.run=^TestLockReleasedAfterProcessExit$")
	command.Env = append(os.Environ(), "MARKETPLACE_LOCK_HELPER="+directory)
	require.NoError(t, command.Start())
	t.Cleanup(func() { command.Process.Kill() })
	ready := false
	for attempt := 0; attempt < 100; attempt++ {
		if _, err := os.Stat(filepath.Join(directory, "ready")); err == nil {
			ready = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	require.True(t, ready)
	root, err := os.OpenRoot(directory)
	require.NoError(t, err)
	defer root.Close()
	_, err = filelock.Acquire(root, ".lock")
	require.Error(t, err)
	require.NoError(t, command.Process.Kill())
	_ = command.Wait()
	release, err := filelock.Acquire(root, ".lock")
	require.NoError(t, err)
	release()
}
