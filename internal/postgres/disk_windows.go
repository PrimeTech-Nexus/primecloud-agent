//go:build windows

package postgres

import (
	"os"
	"syscall"
	"unsafe"
)

var (
	kernel32            = syscall.NewLazyDLL("kernel32.dll")
	getDiskFreeSpaceExW = kernel32.NewProc("GetDiskFreeSpaceExW")
)

func getAvailableDiskBytes(path string) (int64, error) {
	if err := os.MkdirAll(path, 0700); err != nil {
		return 0, err
	}
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}

	var freeBytesAvailable int64
	var totalNumberOfBytes int64
	var totalNumberOfFreeBytes int64

	r1, _, errCall := getDiskFreeSpaceExW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(unsafe.Pointer(&freeBytesAvailable)),
		uintptr(unsafe.Pointer(&totalNumberOfBytes)),
		uintptr(unsafe.Pointer(&totalNumberOfFreeBytes)),
	)
	if r1 == 0 {
		return 0, errCall
	}

	return freeBytesAvailable, nil
}
