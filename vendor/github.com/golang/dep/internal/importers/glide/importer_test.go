// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package glide

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

func TestGlideConfig_Convert(t *testing.T) {
	testCases := map[string]struct {
		yaml glideYaml
		lock glideLock
		importertest.TestCase
	}{
		"project": {
			glideYaml{
				Imports: []glidePackage{
					{
						Name:       importertest.Project,
						Repository: importertest.ProjectSrc,
						Reference:  importertest.V2Branch,
					},
				},
			},
			glideLock{
				Imports: []glideLockedPackage{
					{
						Name:       importertest.Project,
						Repository: importertest.ProjectSrc,
						Revision:   importertest.V2PatchRev,
					},
				},
			},
			importertest.TestCase{
				WantSourceRepo: importertest.ProjectSrc,
				WantConstraint: importertest.V2Branch,
				WantRevision:   importertest.V2PatchRev,
				WantVersion:    importertest.V2PatchTag,
			},
		},
		"test project": {
			glideYaml{
				Imports: []glidePackage{
					{
						Name:       importertest.Project,
						Repository: importertest.ProjectSrc,
						Reference:  importertest.V2Branch,
					},
				},
			},
			glideLock{
				Imports: []glideLockedPackage{
					{
						Name:       importertest.Project,
						Repository: importertest.ProjectSrc,
						Revision:   importertest.V2PatchRev,
					},
				},
			},
			importertest.TestCase{
				WantSourceRepo: importertest.ProjectSrc,
				WantConstraint: importertest.V2Branch,
				WantRevision:   importertest.V2PatchRev,
				WantVersion:    importertest.V2PatchTag,
			},
		},
		"yaml only": {
			glideYaml{
				Imports: []glidePackage{
					{
						Name:       importertest.Project,
						Repository: importertest.ProjectSrc,
						Reference:  importertest.V2Branch,
					},
				},
			},
			glideLock{},
			importertest.TestCase{
				WantSourceRepo: importertest.ProjectSrc,
				WantConstraint: importertest.V2Branch,
			},
		},
		"ignored package": {
			glideYaml{
				Ignores: []string{importertest.Project},
			},
			glideLock{},
			importertest.TestCase{
				WantIgnored: []string{importertest.Project},
			},
		},
		"exclude dir": {
			glideYaml{
				ExcludeDirs: []string{"samples"},
			},
			glideLock{},
			importertest.TestCase{
				WantIgnored: []string{importertest.RootProject + "/samples"},
			},
		},
		"exclude dir ignores mismatched package name": {
			glideYaml{
				Name:        "github.com/golang/mismatched-package-name",
				ExcludeDirs: []string{"samples"},
			},
			glideLock{},
			importertest.TestCase{
				WantIgnored: []string{importertest.RootProject + "/samples"},
			},
		},
		"missing package name": {
			glideYaml{
				Imports: []glidePackage{{Name: ""}},
			},
			glideLock{},
			importertest.TestCase{
				WantWarning: "Warning: Skipping project. Invalid glide configuration, Name is required",
			},
		},
		"warn unused os field": {
			glideYaml{
				Imports: []glidePackage{
					{
						Name: importertest.Project,
						OS:   "windows",
					},
				}},
			glideLock{},
			importertest.TestCase{
				WantWarning: "specified an os",
			},
		},
		"warn unused arch field": {
			glideYaml{
				Imports: []glidePackage{
					{
						Name: importertest.Project,
						Arch: "i686",
					},
				}},
			glideLock{},
			importertest.TestCase{
				WantWarning: "specified an arch",
			},
		},
	}

	for name, testCase := range testCases {
		name := name
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			err := testCase.Execute(t, func(logger *log.Logger, sm gps.SourceManager) (*dep.Manifest, *dep.Lock) {
				g := NewImporter(logger, true, sm)
				g.glideConfig = testCase.yaml
				g.glideLock = testCase.lock
				return g.convert(importertest.RootProject)
			})
			if err != nil {
				t.Fatalf("%#v", err)
			}
		})
	}
}

func TestGlideConfig_Import(t *testing.T) {
	h := test.NewHelper(t)
	defer h.Cleanup()

	ctx := importertest.NewTestContext(h)
	sm, err := ctx.SourceManager()
	h.Must(err)
	defer sm.Release()

	h.TempDir(filepath.Join("src", importertest.RootProject))
	h.TempCopy(filepath.Join(importertest.RootProject, glideYamlName), "glide.yaml")
	h.TempCopy(filepath.Join(importertest.RootProject, glideLockName), "glide.lock")
	projectRoot := h.Path(importertest.RootProject)

	// Capture stderr so we can verify output
	verboseOutput := &bytes.Buffer{}
	ctx.Err = log.New(verboseOutput, "", 0)

	g := NewImporter(ctx.Err, false, sm) // Disable verbose so that we don't print values that change each test run
	if !g.HasDepMetadata(projectRoot) {
		t.Fatal("Expected the importer to detect the glide configuration files")
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
