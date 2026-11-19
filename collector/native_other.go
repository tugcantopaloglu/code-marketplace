//go:build !windows

package collector

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
)

func chooseFolder(context.Context, string) (string, error) {
	return "", fmt.Errorf("enter the destination path directly on this platform")
}
func openFolder(path string) error { return OpenBrowser(path) }
func OpenBrowser(url string) error {
	program := "xdg-open"
	if runtime.GOOS == "darwin" {
		program = "open"
	}
	return exec.Command(program, url).Start()
}
func ShowError(message string) { fmt.Println(message) }
