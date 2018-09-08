// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package govendor

import (
	"bytes"
	"log"
	"path/filepath"
	"testing"

	"github.com/golang/dep"
	"github.com/golang/dep/gps"
	"github.com/golang/dep/internal/importers/importertest"
	"github.com/golang/dep/internal/test"
	"github.com/pkg/errors"
)

const testGovendorProjectRoot = "github.com/golang/notexist"

func TestGovendorConfig_Import(t *testing.T) {
	h := test.NewHelper(t)
	defer h.Cleanup()

	ctx := importertest.NewTestContext(h)
	sm, err := ctx.SourceManager()
	h.Must(err)
	defer sm.Release()

	h.TempDir(filepath.Join("src", testGovendorProjectRoot))
	h.TempCopy(filepath.Join(testGovendorProjectRoot, govendorDir, govendorName), "vendor.json")
	projectRoot := h.Path(testGovendorProjectRoot)

	// Capture stderr so we can verify output
	verboseOutput := &bytes.Buffer{}
	ctx.Err = log.New(verboseOutput, "", 0)

	g := NewImporter(ctx.Err, false, sm) // Disable verbose so that we don't print values that change each test run
	if !g.HasDepMetadata(projectRoot) {
		t.Fatal("Expected the importer to detect the govendor configuration files")
	}

	m, l, err := g.Import(projectRoot, testGovendorProjectRoot)
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
			t.Fatalf("expected %s, got %s", want, got)
		}
	}
}

func TestGovendorConfig_Convert(t *testing.T) {
	testCases := map[string]struct {
		file govendorFile
		importertest.TestCase
	}{
		"project": {
			govendorFile{
				Package: []*govendorPackage{
					{
						Path:     importertest.Project,
						Origin:   importertest.ProjectSrc,
						Revision: importertest.V1Rev,
					},
				},
			},
			importertest.TestCase{
				WantSourceRepo: importertest.ProjectSrc,
				WantConstraint: importertest.V1Constraint,
				WantRevision:   importertest.V1Rev,
				WantVersion:    importertest.V1Tag,
			},
		},
		"skipped build tags": {
			govendorFile{
				Ignore: "test linux_amd64",
			},
			importertest.TestCase{
				WantIgnored: nil,
			},
		},
		"ignored external package": {
			govendorFile{
				Ignore: "github.com/sdboyer/deptest k8s.io/apimachinery",
			},
			importertest.TestCase{
				WantIgnored: []string{"github.com/sdboyer/deptest*", "k8s.io/apimachinery*"},
			},
		},
		"ignored internal package": {
			govendorFile{
				Ignore: "samples/ foo/bar",
			},
			importertest.TestCase{
				WantIgnored: []string{importertest.RootProject + "/samples*", importertest.RootProject + "/foo/bar*"},
			},
		},
		"missing package path": {
			govendorFile{
				Package: []*govendorPackage{
					{
						Revision: importertest.V2PatchRev,
					},
				},
			},
			importertest.TestCase{
				WantWarning: "Warning: Skipping project. Invalid govendor configuration, Path is required",
			},
		},
		"missing package revision doesn't cause an error": {
			govendorFile{
				Package: []*govendorPackage{
					{
						Path: importertest.Project,
					},
				},
			},
			importertest.TestCase{
				WantRevision: "",
			},
		},
	}

	for name, testCase := range testCases {
		name := name
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			err := testCase.Execute(t, func(logger *log.Logger, sm gps.SourceManager) (*dep.Manifest, *dep.Lock) {
				g := NewImporter(logger, true, sm)
				g.file = testCase.file
				return g.convert(importertest.RootProject)
			})
			if err != nil {
				t.Fatalf("%#v", err)
			}
		})
	}
}
