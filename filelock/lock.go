package filelock

import (
	"fmt"
	"os"
)

func Acquire(root *os.Root, name string) (func(), error) {
	file, err := root.OpenFile(name, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := lock(file); err != nil {
		file.Close()
		return nil, fmt.Errorf("lock %s: %w", name, err)
	}
	return func() { file.Close() }, nil
}
