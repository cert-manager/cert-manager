// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package godep

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

func TestGodepConfig_Convert(t *testing.T) {
	testCases := map[string]struct {
		importertest.TestCase
		json godepJSON
	}{
		"package without comment": {
			importertest.TestCase{
				WantConstraint: importertest.V1Constraint,
				WantRevision:   importertest.V1Rev,
				WantVersion:    importertest.V1Tag,
			},
			godepJSON{
				Imports: []godepPackage{
					{
						ImportPath: importertest.Project,
						Rev:        importertest.V1Rev,
					},
				},
			},
		},
		"package with comment": {
			importertest.TestCase{
				WantConstraint: importertest.V2Branch,
				WantRevision:   importertest.V2PatchRev,
				WantVersion:    importertest.V2PatchTag,
			},
			godepJSON{
				Imports: []godepPackage{
					{
						ImportPath: importertest.Project,
						Rev:        importertest.V2PatchRev,
						Comment:    importertest.V2Branch,
					},
				},
			},
		},
		"missing package name": {
			importertest.TestCase{
				WantWarning: "Warning: Skipping project. Invalid godep configuration, ImportPath is required",
			},
			godepJSON{
				Imports: []godepPackage{{ImportPath: ""}},
			},
		},
		"missing revision": {
			importertest.TestCase{
				WantWarning: fmt.Sprintf(
					"Warning: Invalid godep configuration, Rev not found for ImportPath %q",
					importertest.Project,
				),
			},
			godepJSON{
				Imports: []godepPackage{
					{
						ImportPath: importertest.Project,
					},
				},
			},
		},
		"package with requirements": {
			importertest.TestCase{
				WantRequired: []string{importertest.Project},
			},
			godepJSON{
				Required: []string{importertest.Project},
			},
		},
		"package with local requirements": {
			importertest.TestCase{
				WantRequired: nil,
			},
			godepJSON{
				Required: []string{"./..."},
			},
		},
	}

	for name, testCase := range testCases {
		name := name
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			err := testCase.Execute(t, func(logger *log.Logger, sm gps.SourceManager) (*dep.Manifest, *dep.Lock) {
				g := NewImporter(logger, true, sm)
				g.json = testCase.json
				return g.convert(importertest.RootProject)
			})
			if err != nil {
				t.Fatalf("%#v", err)
			}
		})
	}
}

func TestGodepConfig_Import(t *testing.T) {
	h := test.NewHelper(t)
	defer h.Cleanup()

	cacheDir := "gps-repocache"
	h.TempDir(cacheDir)
	h.TempDir("src")
	h.TempDir(filepath.Join("src", importertest.RootProject))
	h.TempCopy(filepath.Join(importertest.RootProject, godepPath), "Godeps.json")

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

	g := NewImporter(logger, false, sm) // Disable Verbose so that we don't print values that change each test run
	if !g.HasDepMetadata(projectRoot) {
		t.Fatal("Expected the importer to detect godep configuration file")
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

func TestGodepConfig_JsonLoad(t *testing.T) {
	// This is same as cmd/dep/testdata/init/Godeps.json
	wantJSON := godepJSON{
		Imports: []godepPackage{
			{
				ImportPath: "github.com/sdboyer/deptest",
				Rev:        "3f4c3bea144e112a69bbe5d8d01c1b09a544253f",
			},
			{
				ImportPath: "github.com/sdboyer/deptestdos",
				Rev:        "5c607206be5decd28e6263ffffdcee067266015e",
				Comment:    "v2.0.0",
			},
		},
	}

	h := test.NewHelper(t)
	defer h.Cleanup()

	ctx := importertest.NewTestContext(h)

	h.TempCopy(filepath.Join(importertest.RootProject, godepPath), "Godeps.json")

	projectRoot := h.Path(importertest.RootProject)

	g := NewImporter(ctx.Err, true, nil)
	err := g.load(projectRoot)
	if err != nil {
		t.Fatalf("Error while loading... %v", err)
	}

	if !equalImports(g.json.Imports, wantJSON.Imports) {
		t.Fatalf("Expected imports to be equal. \n\t(GOT): %v\n\t(WNT): %v", g.json.Imports, wantJSON.Imports)
	}
}

// equalImports compares two slices of godepPackage and checks if they are
// equal.
func equalImports(a, b []godepPackage) bool {
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
