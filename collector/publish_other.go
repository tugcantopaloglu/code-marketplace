//go:build !windows

package collector

import "os"

func publishNoReplace(root *os.Root, _ *os.File, temporary, name string) error {
	return root.Link(temporary, name)
}
