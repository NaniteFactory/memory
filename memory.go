package memory

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

//#include <windows.h>
//#include <stdlib.h>
import "C"

// ----------------------------------------------------------------------------
// Package variables; unexported.

var (
	hProcess             = _GetCurrentProcess()
	hModExe              = _GetProcessModuleHandle()
	hModKernel32         = kernel32.Handle()
	kernel32             = syscall.NewLazyDLL("kernel32") // Kernel32 APIs for accessing memory.
	fnGetModuleHandleW   = kernel32.NewProc("GetModuleHandleW").Addr()
	fnGetCurrentProcess  = kernel32.NewProc("GetCurrentProcess").Addr()
	fnVirtualProtectEx   = kernel32.NewProc("VirtualProtectEx").Addr()
	fnWriteProcessMemory = kernel32.NewProc("WriteProcessMemory").Addr()
)

// ----------------------------------------------------------------------------
// System calls; private in this package.

// GetProcessModuleHandle () returns the base address of .exe module.
func _GetProcessModuleHandle() (hModule uintptr) {
	hModule, _, _ = syscall.Syscall(fnGetModuleHandleW, 1, 0, 0, 0) // (HANDLE)GetModuleHandle(NULL);
	// outputdbg.LogPrintln(fmt.Sprintf("GetProcessModuleHandle(): 0x%X", hModule)) //
	return
}

// GetCurrentProcess () returns the handle of current process on which this function runs.
// This function is another simpler version of `func syscall.GetCurrentProcess() (pseudoHandle Handle, err error)`.
func _GetCurrentProcess() (hProcess uintptr) {
	hProcess, _, _ = syscall.Syscall(fnGetCurrentProcess, 0, 0, 0, 0)
	// outputdbg.LogPrintln(fmt.Sprintf("GetCurrentProcess(): 0x%X", hProcess)) //
	return
}

// ----------------------------------------------------------------------------
// Fancy interfaces other than direct system calls.

// GetHandleProcess () returns hProcess.
func GetHandleProcess() uintptr {
	// outputdbg.LogPrintln(fmt.Sprintf("GetHandleProcess(): 0x%X", hProcess)) //
	return hProcess
}

// GetBase () of our main module.
func GetBase() uintptr {
	// outputdbg.LogPrintln(fmt.Sprintf("GetBase(): 0x%X", hModExe)) //
	return hModExe
}

// Unprotect a virtual memory region in order to get a permission to read/write there and get a way to protect it back after that.
// nSize: Integer, the length in bytes.
func Unprotect(whereFrom, nSize uintptr) (protectBack func() error, err error) {
	var oldProtect C.DWORD
	ret, _, err := syscall.Syscall6(
		fnVirtualProtectEx,
		5, hProcess, whereFrom, nSize, C.PAGE_EXECUTE_READWRITE, uintptr(unsafe.Pointer(&oldProtect)), 0,
	)
	// outputdbg.LogPrintln(ret, err) //
	if ret != 1 {
		return nil, errors.New(fmt.Sprint("Return code ", ret, ": ", err))
	}
	return func() error {
		ret, _, err := syscall.Syscall6(
			fnVirtualProtectEx,
			5, hProcess, whereFrom, nSize, uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)), 0,
		)
		// outputdbg.LogPrintln(ret, err) //
		if ret != 1 {
			return errors.New(fmt.Sprint("Return code ", ret, ": ", err))
		}
		return nil
	}, nil
}

// WriteProcessMemory is probably the safest way to write something to memory.
//
// Another way to write something unsafely to a memory region is as in,
//
// arr := (*[6]byte)(unsafe.Pointer(uintptr(0x004014D0))) // Where to write.
// *arr = [6]byte{0x90, 0x90, 0x90, 0x90, 0x90, 0x90}     // AOB what to write.
//
func WriteProcessMemory(whereFrom uintptr, writeWhat []byte) error {
	whatInHeap := C.CBytes(writeWhat)
	defer C.free(whatInHeap)
	syscall.Write(syscall.Handle(os.Stdout.Fd()), nil) // The reason we do this is because otherwise the syscall below will raise a fault.
	ret, _, err := syscall.Syscall6(
		fnWriteProcessMemory,
		4, hProcess, whereFrom, uintptr(whatInHeap), uintptr(len(writeWhat)), 0, 0,
	)
	// outputdbg.LogPrintln(ret, err) //
	if ret != 1 {
		return errors.New(fmt.Sprint("Return code ", ret, ": ", err))
	}
	return nil
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
