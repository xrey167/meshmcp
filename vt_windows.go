//go:build windows

package main

import (
	"os"
	"syscall"
	"unsafe"
)

// enableVT turns on ANSI escape-sequence processing for the Windows console
// (ENABLE_VIRTUAL_TERMINAL_PROCESSING), so the coloured CLI output renders as
// colour rather than literal escape codes. Best-effort: any failure (an older
// console, a redirected handle) leaves the mode untouched — detectColor has
// already confirmed a character device, and the SGR codes degrade to plain.
func enableVT() {
	const enableVirtualTerminalProcessing = 0x0004
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getConsoleMode := kernel32.NewProc("GetConsoleMode")
	setConsoleMode := kernel32.NewProc("SetConsoleMode")
	handle := syscall.Handle(os.Stdout.Fd())
	var mode uint32
	if r, _, _ := getConsoleMode.Call(uintptr(handle), uintptr(unsafe.Pointer(&mode))); r == 0 {
		return
	}
	_, _, _ = setConsoleMode.Call(uintptr(handle), uintptr(mode|enableVirtualTerminalProcessing))
}
