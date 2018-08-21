// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gvt

import (
	"bytes"
	"fmt"
	"log"
	"path/filepath"
	"testing"

	"github.com/golang/dep"
	"github.com/golang/dep/gps"
	"github.com/golang/dep/internal/importers/importertest"
	"github.com/golang/dep/internal/test"
	"github.com/pkg/errors"
)

func TestGvtConfig_Convert(t *testing.T) {
	testCases := map[string]struct {
		importertest.TestCase
		gvtConfig gvtManifest
	}{
		"package with master branch": {
			importertest.TestCase{
				WantConstraint: importertest.V1Constraint,
				WantRevision:   importertest.V1Rev,
				WantVersion:    importertest.V1Tag,
			},
			gvtManifest{
				Deps: []gvtPkg{
					{
						ImportPath: importertest.Project,
						Revision:   importertest.V1Rev,
						Branch:     "master",
					},
				},
			},
		},
		"package with non-master branch": {
			importertest.TestCase{
				WantConstraint: importertest.V2Branch,
				WantRevision:   importertest.V2PatchRev,
				WantVersion:    importertest.V2PatchTag,
			},
			gvtManifest{
				Deps: []gvtPkg{
					{
						ImportPath: importertest.Project,
						Revision:   importertest.V2PatchRev,
						Branch:     importertest.V2Branch,
					},
				},
			},
		},
		"package with HEAD branch": {
			importertest.TestCase{
				WantRevision: importertest.V1Rev,
				WantVersion:  importertest.V1Tag,
			},
			gvtManifest{
				Deps: []gvtPkg{
					{
						ImportPath: importertest.Project,
						Revision:   importertest.V1Rev,
						Branch:     "HEAD",
					},
				},
			},
		},
		"package with alternate repository": {
			importertest.TestCase{
				WantConstraint: importertest.V1Constraint,
				WantRevision:   importertest.V1Rev,
				WantVersion:    importertest.V1Tag,
				WantSourceRepo: importertest.ProjectSrc,
			},
			gvtManifest{
				Deps: []gvtPkg{
					{
						ImportPath: importertest.Project,
						Repository: importertest.ProjectSrc,
						Revision:   importertest.V1Rev,
						Branch:     "master",
					},
				},
			},
		},
		"missing package name": {
			importertest.TestCase{
				WantWarning: "Warning: Skipping project. Invalid gvt configuration, ImportPath is required",
			},
			gvtManifest{
				Deps: []gvtPkg{{ImportPath: ""}},
			},
		},
		"missing revision": {
			importertest.TestCase{
				WantWarning: fmt.Sprintf(
					"Warning: Invalid gvt configuration, Revision not found for ImportPath %q",
					importertest.Project,
				),
			},
			gvtManifest{
				Deps: []gvtPkg{
					{
						ImportPath: importertest.Project,
					},
				},
			},
		},
	}

	for name, testCase := range testCases {
		name := name
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			err := testCase.Execute(t, func(logger *log.Logger, sm gps.SourceManager) (*dep.Manifest, *dep.Lock) {
				g := NewImporter(logger, true, sm)
				g.gvtConfig = testCase.gvtConfig
				return g.convert(importertest.RootProject)
			})
			if err != nil {
				t.Fatalf("%#v", err)
			}
		})
	}
}

func TestGvtConfig_Import(t *testing.T) {
	h := test.NewHelper(t)
	defer h.Cleanup()

	cacheDir := "gps-repocache"
	h.TempDir(cacheDir)
	h.TempDir("src")
	h.TempDir(filepath.Join("src", importertest.RootProject))
	h.TempCopy(filepath.Join(importertest.RootProject, gvtPath), "manifest")

	projectRoot := h.Path(importertest.RootProject)
	sm, err := gps.NewSourceManager(gps.SourceManagerConfig{
		Cachedir: h.Path(cacheDir),
		Logger:   log.New(test.Writer{TB: t}, "", 0),
	})
	h.Must(err)
	defer sm.Release()

	// Capture stderr so we can verify output
	verboseOutput := &bytes.Buffer{}
	logger := log.New(verboseOutput, "", 0)

	g := NewImporter(logger, false, sm) // Disable verbose so that we don't print values that change each test run
	if !g.HasDepMetadata(projectRoot) {
		t.Fatal("Expected the importer to detect gvt configuration file")
	}

	m, l, err := g.Import(projectRoot, importertest.RootProject)
	h.Must(err)

	if m == nil {
		t.Fatal("Expected the manifest to be generated")
	}

	if l == nil {
		t.Fatal("Expected the lock to be generated")
	}

	goldenFile := "golden.txt"
	got := verboseOutput.String()
	want := h.GetTestFileString(goldenFile)
	if want != got {
		if *test.UpdateGolden {
			if err := h.WriteTestFile(goldenFile, got); err != nil {
				t.Fatalf("%+v", errors.Wrapf(err, "Unable to write updated golden file %s", goldenFile))
			}
		} else {
			t.Fatalf("want %s, got %s", want, got)
		}
	}
}

func TestGvtConfig_JsonLoad(t *testing.T) {
	// This is same as testdata/manifest
	wantConfig := gvtManifest{
		Deps: []gvtPkg{
			{
				ImportPath: "github.com/sdboyer/deptest",
				Revision:   "3f4c3bea144e112a69bbe5d8d01c1b09a544253f",
				Branch:     "HEAD",
			},
			{
				ImportPath: "github.com/sdboyer/deptestdos",
				Revision:   "5c607206be5decd28e6263ffffdcee067266015e",
				Branch:     "master",
			},
			{
				ImportPath: "github.com/carolynvs/deptest-importers",
				Revision:   "b79bc9482da8bb7402cdc3e3fd984db250718dd7",
				Branch:     "v2",
			},
		},
	}

	h := test.NewHelper(t)
	defer h.Cleanup()

	ctx := importertest.NewTestContext(h)

	h.TempCopy(filepath.Join(importertest.RootProject, gvtPath), "manifest")

	projectRoot := h.Path(importertest.RootProject)

	g := NewImporter(ctx.Err, true, nil)
	err := g.load(projectRoot)
	if err != nil {
		t.Fatalf("Error while loading... %v", err)
	}

	if !equalImports(g.gvtConfig.Deps, wantConfig.Deps) {
		t.Fatalf("Expected imports to be equal. \n\t(GOT): %v\n\t(WNT): %v", g.gvtConfig.Deps, wantConfig.Deps)
	}
}

// equalImports compares two slices of gvtPkg and checks if they are
// equal.
func equalImports(a, b []gvtPkg) bool {
	if a == nil && b == nil {
		return true
	}

	if a == nil || b == nil {
		return false
	}

	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}
