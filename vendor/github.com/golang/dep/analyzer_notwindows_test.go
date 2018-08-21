// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !windows

package dep

import (
	"io"
	"os"
)

func makeUnreadable(path string) (io.Closer, error) {
	err := os.Chmod(path, 0222)
	if err != nil {
		return nil, err
	}
	return closer{}, nil
}

type closer struct{}

func (closer) Close() error { return nil }
