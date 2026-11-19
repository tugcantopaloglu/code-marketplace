//go:build windows

package collector

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func hiddenCommand(ctx context.Context, name string, args ...string) *exec.Cmd {
	command := exec.CommandContext(ctx, name, args...)
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000}
	return command
}

var (
	shell          = windows.NewLazySystemDLL("shell32.dll")
	ole            = windows.NewLazySystemDLL("ole32.dll")
	user           = windows.NewLazySystemDLL("user32.dll")
	browseFolder   = shell.NewProc("SHBrowseForFolderW")
	pathFromID     = shell.NewProc("SHGetPathFromIDListEx")
	sendMessage    = user.NewProc("SendMessageW")
	postMessage    = user.NewProc("PostMessageW")
	foreground     = user.NewProc("SetForegroundWindow")
	showWindow     = user.NewProc("ShowWindow")
	folderCallback = syscall.NewCallback(folderInitialized)
	folderStates   sync.Map
	folderSequence atomic.Uintptr
)

type browseInfo struct {
	Owner, Root        uintptr
	DisplayName, Title *uint16
	Flags              uint32
	Callback, Param    uintptr
	Image              int32
}

type folderState struct {
	initial []uint16
	ready   chan uintptr
}

func folderInitialized(hwnd uintptr, message uint32, _, data uintptr) uintptr {
	if message == 1 { // BFFM_INITIALIZED
		value, ok := folderStates.Load(data)
		if !ok {
			return 0
		}
		state := value.(*folderState)
		sendMessage.Call(hwnd, 0x467, 1, uintptr(unsafe.Pointer(&state.initial[0]))) // BFFM_SETSELECTIONW
		// Deployers may launch the EXE with STARTUPINFO/SW_HIDE. ShowWindow's
		// first call honors that startup flag, so explicitly show it afterwards.
		showWindow.Call(hwnd, 5)
		showWindow.Call(hwnd, 5)
		foreground.Call(hwnd)
		state.ready <- hwnd
	}
	return 0
}

func chooseFolder(ctx context.Context, initial string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	initialized, _, _ := ole.NewProc("CoInitializeEx").Call(0, 2) // COINIT_APARTMENTTHREADED
	if int32(initialized) < 0 {
		return "", fmt.Errorf("folder COM initialization failed: %x", initialized)
	}
	defer ole.NewProc("CoUninitialize").Call()
	title, _ := windows.UTF16PtrFromString("Paketlerin kaydedileceği klasörü seçin")
	initialPath, err := windows.UTF16FromString(initial)
	if err != nil {
		return "", err
	}
	state := &folderState{initial: initialPath, ready: make(chan uintptr, 1)}
	stateID := folderSequence.Add(1)
	folderStates.Store(stateID, state)
	defer folderStates.Delete(stateID)
	display := make([]uint16, 260)
	info := browseInfo{Title: title, DisplayName: &display[0], Flags: 0x51, Callback: folderCallback, Param: stateID}
	done := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
			select {
			case hwnd := <-state.ready:
				postMessage.Call(hwnd, 0x10, 0, 0)
			case <-done:
			}
		case <-done:
		}
	}()
	pidl, _, _ := browseFolder.Call(uintptr(unsafe.Pointer(&info)))
	close(done)
	<-watcherDone
	if pidl == 0 {
		return "", ctx.Err()
	}
	defer ole.NewProc("CoTaskMemFree").Call(pidl)
	buffer := make([]uint16, 32768)
	ok, _, _ := pathFromID.Call(pidl, uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), 0)
	if ok == 0 {
		return "", fmt.Errorf("selected item is not a filesystem folder")
	}
	return windows.UTF16ToString(buffer), nil
}

func startDetached(command *exec.Cmd) error {
	if err := command.Start(); err != nil {
		return err
	}
	return command.Process.Release()
}

func openFolder(path string) error { return startDetached(exec.Command("explorer.exe", path)) }

func OpenBrowser(url string) error {
	return startDetached(hiddenCommand(context.Background(), "rundll32.exe", "url.dll,FileProtocolHandler", url))
}

func ShowError(message string) {
	text, _ := windows.UTF16PtrFromString(message)
	title, _ := windows.UTF16PtrFromString("Code Marketplace")
	user.NewProc("MessageBoxW").Call(0, uintptr(unsafe.Pointer(text)), uintptr(unsafe.Pointer(title)), 0x10)
}
