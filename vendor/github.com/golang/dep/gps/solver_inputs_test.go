// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gps

import (
	"io/ioutil"
	"log"
	"math/rand"
	"strconv"
	"strings"
	"testing"

	"github.com/golang/dep/gps/pkgtree"
	"github.com/golang/dep/internal/test"
)

// TestBadSolveOpts exercises the different possible inputs to a solver that can
// be determined as invalid in Prepare(), without any further work
func TestBadSolveOpts(t *testing.T) {
	pn := strconv.FormatInt(rand.Int63(), 36)
	fix := basicFixtures["no dependencies"]
	fix.ds[0].n = ProjectRoot(pn)

	sm := newdepspecSM(fix.ds, nil)
	params := SolveParameters{
		mkBridgeFn: overrideMkBridge,
	}

	_, err := Prepare(params, nil)
	if err == nil {
		t.Errorf("Prepare should have errored on nil SourceManager")
	} else if !strings.Contains(err.Error(), "non-nil SourceManager") {
		t.Error("Prepare should have given error on nil SourceManager, but gave:", err)
	}

	_, err = Prepare(params, sm)
	if err == nil {
		t.Errorf("Prepare should have errored without ProjectAnalyzer")
	} else if !strings.Contains(err.Error(), "must provide a ProjectAnalyzer") {
		t.Error("Prepare should have given error without ProjectAnalyzer, but gave:", err)
	}

	params.ProjectAnalyzer = naiveAnalyzer{}
	_, err = Prepare(params, sm)
	if err == nil {
		t.Errorf("Prepare should have errored on empty root")
	} else if !strings.Contains(err.Error(), "non-empty root directory") {
		t.Error("Prepare should have given error on empty root, but gave:", err)
	}

	params.RootDir = pn
	_, err = Prepare(params, sm)
	if err == nil {
		t.Errorf("Prepare should have errored on empty name")
	} else if !strings.Contains(err.Error(), "non-empty import root") {
		t.Error("Prepare should have given error on empty import root, but gave:", err)
	}

	params.RootPackageTree = pkgtree.PackageTree{
		ImportRoot: pn,
	}
	_, err = Prepare(params, sm)
	if err == nil {
		t.Errorf("Prepare should have errored on empty name")
	} else if !strings.Contains(err.Error(), "at least one package") {
		t.Error("Prepare should have given error on empty import root, but gave:", err)
	}

	params.RootPackageTree = pkgtree.PackageTree{
		ImportRoot: pn,
		Packages: map[string]pkgtree.PackageOrErr{
			pn: {
				P: pkgtree.Package{
					ImportPath: pn,
					Name:       pn,
				},
			},
		},
	}
	params.TraceLogger = log.New(ioutil.Discard, "", 0)

	params.Manifest = simpleRootManifest{
		ovr: ProjectConstraints{
			ProjectRoot("foo"): ProjectProperties{},
		},
	}
	_, err = Prepare(params, sm)
	if err == nil {
		t.Errorf("Should have errored on override with empty ProjectProperties")
	} else if !strings.Contains(err.Error(), "foo, but without any non-zero properties") {
		t.Error("Prepare should have given error override with empty ProjectProperties, but gave:", err)
	}

	params.Manifest = simpleRootManifest{
		ig:  pkgtree.NewIgnoredRuleset([]string{"foo"}),
		req: map[string]bool{"foo": true},
	}
	_, err = Prepare(params, sm)
	if err == nil {
		t.Errorf("Should have errored on pkg both ignored and required")
	} else if !strings.Contains(err.Error(), "was given as both a required and ignored package") {
		t.Error("Prepare should have given error with single ignore/require conflict error, but gave:", err)
	}

	params.Manifest = simpleRootManifest{
		ig:  pkgtree.NewIgnoredRuleset([]string{"foo", "bar"}),
		req: map[string]bool{"foo": true, "bar": true},
	}
	_, err = Prepare(params, sm)
	if err == nil {
		t.Errorf("Should have errored on pkg both ignored and required")
	} else if !strings.Contains(err.Error(), "multiple packages given as both required and ignored:") {
		t.Error("Prepare should have given error with multiple ignore/require conflict error, but gave:", err)
	}

	params.Manifest = simpleRootManifest{
		ig:  pkgtree.NewIgnoredRuleset([]string{"foo*"}),
		req: map[string]bool{"foo/bar": true},
	}
	_, err = Prepare(params, sm)
	if err == nil {
		t.Errorf("Should have errored on pkg both ignored (with wildcard) and required")
	} else if !strings.Contains(err.Error(), "was given as both a required and ignored package") {
		t.Error("Prepare should have given error with single ignore/require conflict error, but gave:", err)
	}
	params.Manifest = nil

	params.ToChange = []ProjectRoot{"foo"}
	_, err = Prepare(params, sm)
	if err == nil {
		t.Errorf("Should have errored on non-empty ToChange without a lock provided")
	} else if !strings.Contains(err.Error(), "update specifically requested for") {
		t.Error("Prepare should have given error on ToChange without Lock, but gave:", err)
	}

	params.Lock = safeLock{
		p: []LockedProject{
			NewLockedProject(mkPI("bar"), Revision("makebelieve"), nil),
		},
	}
	_, err = Prepare(params, sm)
	if err == nil {
		t.Errorf("Should have errored on ToChange containing project not in lock")
	} else if !strings.Contains(err.Error(), "cannot update foo as it is not in the lock") {
		t.Error("Prepare should have given error on ToChange with item not present in Lock, but gave:", err)
	}

	params.Lock, params.ToChange = nil, nil
	_, err = Prepare(params, sm)
	if err != nil {
		t.Error("Basic conditions satisfied, prepare should have completed successfully, err as:", err)
	}

	// swap out the test mkBridge override temporarily, just to make sure we get
	// the right error
	params.mkBridgeFn = nil

	_, err = Prepare(params, sm)
	if err == nil {
		t.Errorf("Should have errored on nonexistent root")
	} else if !strings.Contains(err.Error(), "could not read project root") {
		t.Error("Prepare should have given error nonexistent project root dir, but gave:", err)
	}

	// Pointing it at a file should also be an err
	params.RootDir = "solve_test.go"
	_, err = Prepare(params, sm)
	if err == nil {
		t.Errorf("Should have errored on file for RootDir")
	} else if !strings.Contains(err.Error(), "is a file, not a directory") {
		t.Error("Prepare should have given error on file as RootDir, but gave:", err)
	}
}

func TestValidateParams(t *testing.T) {
	h := test.NewHelper(t)
	defer h.Cleanup()

	cacheDir := "gps-cache"
	h.TempDir(cacheDir)
	sm, err := NewSourceManager(SourceManagerConfig{
		Cachedir: h.Path(cacheDir),
		Logger:   log.New(test.Writer{TB: t}, "", 0),
	})
	h.Must(err)
	defer sm.Release()

	h.TempDir("src")

	testcases := []struct {
		imports []string
		err     bool
	}{
		{[]string{"google.com/non-existing/package"}, true},
		{[]string{"google.com/non-existing/package/subpkg"}, true},
		{[]string{"github.com/sdboyer/testrepo"}, false},
		{[]string{"github.com/sdboyer/testrepo/subpkg"}, false},
	}

	params := SolveParameters{
		ProjectAnalyzer: naiveAnalyzer{},
		RootDir:         h.Path("src"),
		RootPackageTree: pkgtree.PackageTree{
			ImportRoot: "github.com/sdboyer/dep",
		},
	}

	for _, tc := range testcases {
		params.RootPackageTree.Packages = map[string]pkgtree.PackageOrErr{
			"github.com/sdboyer/dep": {
				P: pkgtree.Package{
					Name:       "github.com/sdboyer/dep",
					ImportPath: "github.com/sdboyer/dep",
					Imports:    tc.imports,
				},
			},
		}

		err = ValidateParams(params, sm)
		if tc.err && err == nil {
			t.Fatalf("expected an error when deducing package fails, got none")
		} else if !tc.err && err != nil {
			t.Fatalf("deducing packges should have succeeded, got err: %#v", err)
		}
	}
}
