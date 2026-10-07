package storage

import (
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func publishDirectory(directory, staging, destination string) error {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer root.Close()
	target, err := filepath.Rel(directory, destination)
	if err != nil {
		return err
	}
	source := filepath.Base(staging)
	lock := fmt.Sprintf(".lock-%x", sha256.Sum256([]byte(strings.ToLower(filepath.ToSlash(target)))))
	file, err := root.OpenFile(lock, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("package is being updated: %w", err)
	}
	file.Close()
	defer root.Remove(lock)
	if _, err := root.Stat(target); os.IsNotExist(err) {
		return root.Rename(source, target)
	} else if err != nil {
		return err
	}
	err = fs.WalkDir(root.FS(), filepath.ToSlash(target), func(_ string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return fmt.Errorf("existing package contains a symlink")
		}
		return nil
	})
	if err != nil {
		return err
	}
	err = filepath.WalkDir(staging, func(location string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(staging, location)
		if err != nil {
			return err
		}
		if current, err := root.Stat(filepath.Join(target, relative)); err == nil && current.IsDir() {
			return fmt.Errorf("existing asset is a directory")
		}
		return nil
	})
	if err != nil {
		return err
	}
	backup, err := os.MkdirTemp(directory, ".previous-")
	if err != nil {
		return err
	}
	if err := os.Remove(backup); err != nil {
		return err
	}
	backupName := filepath.Base(backup)
	if err := root.Rename(target, backupName); err != nil {
		return err
	}
	if err := root.Rename(source, target); err != nil {
		if restore := root.Rename(backupName, target); restore != nil {
			return fmt.Errorf("publish: %v; restore: %w", err, restore)
		}
		return err
	}
	return root.RemoveAll(backupName)
}
