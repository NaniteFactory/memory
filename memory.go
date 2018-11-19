package memory

import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/nanitefactory/outputdbg"
)

//#include <Windows.h>
import "C"

// ----------------------------------------------------------------------------
// Package variables; unexported.

var (
	hProcess            = _GetCurrentProcess()
	hModExe             = _GetProcessModuleHandle()
	hModKernel32        = kernel32.Handle()
	kernel32            = syscall.NewLazyDLL("kernel32.dll") // Kernel32 APIs for accessing memory.
	fnGetModuleHandleW  = kernel32.NewProc("GetModuleHandleW").Addr()
	fnGetCurrentProcess = kernel32.NewProc("GetCurrentProcess").Addr()
)

// ----------------------------------------------------------------------------
// System calls; private in this package.

// GetProcessModuleHandle () returns the base address of .exe module.
func _GetProcessModuleHandle() (hModule uintptr) {
	hModule, _, _ = syscall.Syscall(fnGetModuleHandleW, 1, 0, 0, 0)              // (HANDLE)GetModuleHandle(NULL);
	outputdbg.LogPrintln(fmt.Sprintf("GetProcessModuleHandle(): 0x%X", hModule)) //
	return
}

// GetCurrentProcess () returns the handle of current process on which this function runs.
// This function is another simpler version of `func syscall.GetCurrentProcess() (pseudoHandle Handle, err error)`.
func _GetCurrentProcess() (hProcess uintptr) {
	hProcess, _, _ = syscall.Syscall(fnGetCurrentProcess, 0, 0, 0, 0)
	return
}

// ----------------------------------------------------------------------------
// Fancy interfaces other than direct system calls.

// GetHandleProcess () returns hProcess.
func GetHandleProcess() uintptr {
	outputdbg.LogPrintln(fmt.Sprintf("GetHandleProcess(): 0x%X", hProcess)) //
	return hProcess
}

// GetHookPoint () in our process.
func GetHookPoint(offset uintptr) (hookPoint uintptr) {
	base := hModExe
	hookPoint = base + offset
	outputdbg.LogPrintln(fmt.Sprintf("GetHookPoint(): 0x%X = 0x%X + 0x%X", hookPoint, base, offset)) //
	return
}

// GetBase () of our main module.
func GetBase() uintptr {
	// outputdbg.LogPrintln(fmt.Sprintf("GetBase(): 0x%X", hModExe)) //
	return hModExe
}

// GetPtrUnsafe () returns a ptr. Params must be in order.
//
// This function can cause a fatal for accessing a fault address,
// which just terminates the entire program and can't be handled any way.
//
// e.g.
// ```
// unexpected fault address 0xdd7ae08
// fatal error: fault
// ```
//
// There are other types of panic that can be handeled though.
// To catch and handle the other kinds of thrown exceptions,
// such as "runtime error: invalid memory address or nil pointer dereference",
// you might want to do something like this below:
//
// defer func() {
// 	r := recover()
// 	if r != nil {
// 		err = r.(error)
// 	}
// }()
//
// In a nutshell,
// you just can't recover from the invalid memory access error (unexpected fault address),
// while the nil ptr exception can be handled at runtime.
//
func GetPtrUnsafe(_base uintptr, _offsets ...uintptr) (ptr uintptr) {
	ptr = _base
	base := *(*uintptr)(unsafe.Pointer(ptr))
	for _, offset := range _offsets {
		// prev := base //
		ptr = base + offset
		base = *(*uintptr)(unsafe.Pointer(ptr))
		// outputdbg.LogPrintln(fmt.Sprintf("[%x + %x = %x] = %x", prev, offset, ptr, base)) //
	}
	return ptr
}

// GetValUnsafe () returns a ptr. Params must be in order.
//
// This function can cause a fatal for accessing a fault address,
// which just terminates the entire program and can't be handled any way.
//
// e.g.
// ```
// unexpected fault address 0xdd7ae08
// fatal error: fault
// ```
//
// There are other types of panic that can be handled though.
// To catch and handle the other kinds of thrown exceptions,
// such as "runtime error: invalid memory address or nil pointer dereference",
// you might want to do something like this below:
//
// defer func() {
// 	r := recover()
// 	if r != nil {
// 		err = r.(error)
// 	}
// }()
//
// In summary,
// you just can't recover from the invalid memory access error (unexpected fault address),
// while the nil ptr exception can be handled at runtime.
//
func GetValUnsafe(base uintptr, offsets ...uintptr) (val uintptr) {
	return *(*uintptr)(unsafe.Pointer(GetPtrUnsafe(base, offsets...)))
}
