// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dep

import (
	"io"
	"os"
	"syscall"
)

// makeUnreadable opens the file at path in exclusive mode. A file opened in
// exclusive mode cannot be opened again until the exclusive mode file handle
// is closed.
func makeUnreadable(path string) (io.Closer, error) {
	if len(path) == 0 {
		return nil, syscall.ERROR_FILE_NOT_FOUND
	}
	pathp, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	access := uint32(syscall.GENERIC_READ | syscall.GENERIC_WRITE)
	sharemode := uint32(0) // no sharing == exclusive mode
	sa := (*syscall.SecurityAttributes)(nil)
	createmode := uint32(syscall.OPEN_EXISTING)
	h, err := syscall.CreateFile(pathp, access, sharemode, sa, createmode, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(h), path), nil
}
