// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package glock

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

func TestGlockConfig_Convert(t *testing.T) {
	testCases := map[string]struct {
		importertest.TestCase
		packages []glockPackage
	}{
		"package": {
			importertest.TestCase{
				WantConstraint: importertest.V1Constraint,
				WantRevision:   importertest.V1Rev,
				WantVersion:    importertest.V1Tag,
			},
			[]glockPackage{
				{
					importPath: importertest.Project,
					revision:   importertest.V1Rev,
				},
			},
		},
		"missing package name": {
			importertest.TestCase{
				WantWarning: "Warning: Skipping project. Invalid glock configuration, import path is required",
			},
			[]glockPackage{{importPath: ""}},
		},
		"missing revision": {
			importertest.TestCase{
				WantWarning: fmt.Sprintf(
					"  Warning: Skipping import with empty constraints. "+
						"The solve step will add the dependency to the lock if needed: %q",
					importertest.Project,
				),
			},
			[]glockPackage{{importPath: importertest.Project}},
		},
	}

	for name, testCase := range testCases {
		name := name
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			err := testCase.Execute(t, func(logger *log.Logger, sm gps.SourceManager) (*dep.Manifest, *dep.Lock) {
				g := NewImporter(logger, true, sm)
				g.packages = testCase.packages
				return g.convert(importertest.RootProject)
			})
			if err != nil {
				t.Fatalf("%#v", err)
			}
		})
	}
}

func TestGlockConfig_LoadInvalid(t *testing.T) {
	const testLine = "github.com/sdboyer/deptest 3f4c3bea144e112a69bbe5d8d01c1b09a544253f invalid"
	_, err := parseGlockLine(testLine)
	expected := fmt.Errorf("invalid glock configuration: %s", testLine)
	if err.Error() != expected.Error() {
		t.Errorf("want error %s, got %s", err, expected)
	}
}

func TestGlockConfig_LoadEmptyLine(t *testing.T) {
	pkg, err := parseGlockLine("")
	if err != nil {
		t.Fatalf("%#v", err)
	}
	if pkg != nil {
		t.Errorf("want package nil, got %+v", pkg)
	}
}

func TestGlockConfig_Import(t *testing.T) {
	h := test.NewHelper(t)
	defer h.Cleanup()

	ctx := importertest.NewTestContext(h)
	sm, err := ctx.SourceManager()
	h.Must(err)
	defer sm.Release()

	h.TempDir(filepath.Join("src", importertest.RootProject))
	h.TempCopy(filepath.Join(importertest.RootProject, glockfile), glockfile)
	projectRoot := h.Path(importertest.RootProject)

	// Capture stderr so we can verify output
	verboseOutput := &bytes.Buffer{}
	ctx.Err = log.New(verboseOutput, "", 0)

	g := NewImporter(ctx.Err, false, sm) // Disable verbose so that we don't print values that change each test run
	if !g.HasDepMetadata(projectRoot) {
		t.Fatal("Expected the importer to detect the glock configuration files")
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
