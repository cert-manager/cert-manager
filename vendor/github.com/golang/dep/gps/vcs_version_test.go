// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gps

import (
	"path/filepath"
	"testing"

	"github.com/golang/dep/internal/test"
)

func TestVCSVersion(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping slow test in short mode")
	}

	h := test.NewHelper(t)
	defer h.Cleanup()
	requiresBins(t, "git")

	h.TempDir("src")
	gopath := h.Path(".")
	h.Setenv("GOPATH", gopath)

	importPaths := map[string]struct {
		rev      Version
		checkout bool
	}{
		"github.com/pkg/errors": {
			rev:      NewVersion("v0.8.0").Pair("645ef00459ed84a119197bfb8d8205042c6df63d"), // semver
			checkout: true,
		},
		"github.com/sirupsen/logrus": {
			rev:      Revision("42b84f9ec624953ecbf81a94feccb3f5935c5edf"), // random sha
			checkout: true,
		},
		"github.com/rsc/go-get-default-branch": {
			rev: NewBranch("another-branch").Pair("8e6902fdd0361e8fa30226b350e62973e3625ed5"),
		},
	}

	// checkout the specified revisions
	for ip, info := range importPaths {
		h.RunGo("get", ip)
		repoDir := h.Path("src/" + ip)
		if info.checkout {
			h.RunGit(repoDir, "checkout", info.rev.String())
		}
		abs := filepath.FromSlash(filepath.Join(gopath, "src", ip))
		got, err := VCSVersion(abs)
		h.Must(err)

		if got != info.rev {
			t.Fatalf("expected %q, got %q", got.String(), info.rev.String())
		}
	}
}
