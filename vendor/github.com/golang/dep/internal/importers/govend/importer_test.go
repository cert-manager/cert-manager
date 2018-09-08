// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package govend

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

func TestGovendConfig_Convert(t *testing.T) {
	testCases := map[string]struct {
		yaml govendYAML
		importertest.TestCase
	}{
		"package": {
			govendYAML{
				Imports: []govendPackage{
					{
						Path:     importertest.Project,
						Revision: importertest.V1Rev,
					},
				},
			},
			importertest.TestCase{
				WantConstraint: importertest.V1Constraint,
				WantRevision:   importertest.V1Rev,
				WantVersion:    importertest.V1Tag,
			},
		},
		"missing package name": {
			govendYAML{
				Imports: []govendPackage{
					{
						Path: "",
					},
				},
			},
			importertest.TestCase{
				WantWarning: "Warning: Skipping project. Invalid govend configuration, path is required",
			},
		},

		"missing revision": {
			govendYAML{
				Imports: []govendPackage{
					{
						Path: importertest.Project,
					},
				},
			},
			importertest.TestCase{
				WantWarning: fmt.Sprintf(
					"  Warning: Skipping import with empty constraints. "+
						"The solve step will add the dependency to the lock if needed: %q\n",
					importertest.Project,
				),
			},
		},
	}

	for name, testCase := range testCases {
		name := name
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			err := testCase.Execute(t, func(logger *log.Logger, sm gps.SourceManager) (*dep.Manifest, *dep.Lock) {
				g := NewImporter(logger, true, sm)
				g.yaml = testCase.yaml
				return g.convert(importertest.RootProject)
			})
			if err != nil {
				t.Fatalf("%#v", err)
			}
		})
	}
}

func TestGovendConfig_Import(t *testing.T) {
	h := test.NewHelper(t)
	defer h.Cleanup()

	cacheDir := "gps-repocache"
	h.TempDir(cacheDir)
	h.TempDir("src")
	h.TempDir(filepath.Join("src", importertest.RootProject))
	h.TempCopy(filepath.Join(importertest.RootProject, govendYAMLName), "vendor.yml")

	projectRoot := h.Path(importertest.RootProject)
	sm, err := gps.NewSourceManager(gps.SourceManagerConfig{Cachedir: h.Path(cacheDir)})
	h.Must(err)
	defer sm.Release()

	// Capture stderr so we can verify the import output
	verboseOutput := &bytes.Buffer{}
	logger := log.New(verboseOutput, "", 0)

	// Disable Verbose so that we don't print values that change each test run
	g := NewImporter(logger, false, sm)
	if !g.HasDepMetadata(projectRoot) {
		t.Fatal("Expected the importer to detect govend configuration file")
	}

	m, l, err := g.Import(projectRoot, importertest.RootProject)
	h.Must(err)

	if m == nil {
		t.Fatal("Expected the manifest to be generated")
	}

	if l == nil {
		t.Fatal("Expected the lock to be generated")
	}

	govendImportOutputFile := "golden.txt"
	got := verboseOutput.String()
	want := h.GetTestFileString(govendImportOutputFile)
	if want != got {
		if *test.UpdateGolden {
			if err := h.WriteTestFile(govendImportOutputFile, got); err != nil {
				t.Fatalf("%+v", errors.Wrapf(err, "Unable to write updated golden file %s", govendImportOutputFile))
			}
		} else {
			t.Fatalf("want %s, got %s", want, got)
		}
	}

}

func TestGovendConfig_YAMLLoad(t *testing.T) {
	// This is same as cmd/testdata/init/govend/vendor.yml
	wantYaml := govendYAML{
		Imports: []govendPackage{
			{
				Path:     "github.com/sdboyer/deptest",
				Revision: "3f4c3bea144e112a69bbe5d8d01c1b09a544253f",
			},
			{
				Path:     "github.com/sdboyer/deptestdos",
				Revision: "5c607206be5decd28e6263ffffdcee067266015e",
			},
		},
	}
	h := test.NewHelper(t)
	defer h.Cleanup()

	ctx := importertest.NewTestContext(h)
	h.TempCopy(filepath.Join(importertest.RootProject, govendYAMLName), "vendor.yml")

	projectRoot := h.Path(importertest.RootProject)

	g := NewImporter(ctx.Err, true, nil)
	err := g.load(projectRoot)
	if err != nil {
		t.Fatalf("Error while loading %v", err)
	}

	if !equalGovendImports(g.yaml.Imports, wantYaml.Imports) {
		t.Fatalf("Expected import to be equal. \n\t(GOT): %v\n\t(WNT): %v", g.yaml.Imports, wantYaml.Imports)
	}
}

func equalGovendImports(a, b []govendPackage) bool {
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
