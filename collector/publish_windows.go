//go:build windows

package collector

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

var reopenFile = windows.NewLazySystemDLL("kernel32.dll").NewProc("ReOpenFile")

// Rename the open staging file within its own directory. No pathname lookup of
// the source or destination directory is needed, and an existing name fails.
func publishNoReplace(_ *os.Root, file *os.File, _, name string) error {
	wide, err := windows.UTF16FromString(name)
	if err != nil {
		return err
	}
	info := struct {
		Replace uint32
		Root    windows.Handle
		Length  uint32
		Name    [1024]uint16
	}{}
	if len(wide) > len(info.Name) {
		return fmt.Errorf("output filename too long")
	}
	copy(info.Name[:], wide)
	info.Length = uint32((len(wide) - 1) * 2)
	handle, _, callErr := reopenFile.Call(file.Fd(), windows.DELETE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, 0)
	if windows.Handle(handle) == windows.InvalidHandle {
		return callErr
	}
	defer windows.CloseHandle(windows.Handle(handle))
	var status windows.IO_STATUS_BLOCK
	return windows.NtSetInformationFile(windows.Handle(handle), &status, (*byte)(unsafe.Pointer(&info)), uint32(unsafe.Offsetof(info.Name))+info.Length, windows.FileRenameInformation)
}
