//go:build windows

package main

import (
	"os"
	"syscall"
)

// attachConsole lets the GUI-subsystem binary print to the terminal it was
// started from when used in CLI mode.
func attachConsole() {
	// stdout already redirected to a pipe/file (e.g. `x509-inspector check a.pem > out.txt`): keep it.
	if _, err := os.Stdout.Stat(); err == nil {
		return
	}
	k32 := syscall.NewLazyDLL("kernel32.dll")
	proc := k32.NewProc("AttachConsole")
	const attachParent = ^uintptr(0) // ATTACH_PARENT_PROCESS (-1)
	r, _, _ := proc.Call(attachParent)
	if r == 0 {
		return
	}
	if f, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
		os.Stdout = f
		os.Stderr = f
	}
}
