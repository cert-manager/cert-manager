// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/golang/dep/internal/test"
)

// The TestMain function creates a dep command for testing purposes and
// deletes it after the tests have been run.
// Most of this is taken from https://github.com/golang/go/blob/master/src/cmd/go/go_test.go and reused here.
func TestMain(m *testing.M) {
	args := []string{"build", "-o", "testdep" + test.ExeSuffix}
	out, err := exec.Command("go", args...).CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "building testdep failed: %v\n%s", err, out)
		os.Exit(2)
	}

	// Don't let these environment variables confuse the test.
	os.Unsetenv("GOPATH")
	os.Unsetenv("GIT_ALLOW_PROTOCOL")
	if home, ccacheDir := os.Getenv("HOME"), os.Getenv("CCACHE_DIR"); home != "" && ccacheDir == "" {
		// On some systems the default C compiler is ccache.
		// Setting HOME to a non-existent directory will break
		// those systems.  Set CCACHE_DIR to cope.  Issue 17668.
		os.Setenv("CCACHE_DIR", filepath.Join(home, ".ccache"))
	}
	os.Setenv("HOME", "/test-dep-home-does-not-exist")
	if os.Getenv("GOCACHE") == "" {
		os.Setenv("GOCACHE", "off") // because $HOME is gone
	}

	r := m.Run()

	os.Remove("testdep" + test.ExeSuffix)

	os.Exit(r)
}
