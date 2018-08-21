// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vndr

import (
	"bytes"
	"fmt"
	"log"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/golang/dep"
	"github.com/golang/dep/gps"
	"github.com/golang/dep/internal/importers/importertest"
	"github.com/golang/dep/internal/test"
	"github.com/pkg/errors"
)

func TestVndrConfig_Convert(t *testing.T) {
	testCases := map[string]struct {
		packages []vndrPackage
		importertest.TestCase
	}{
		"package": {
			[]vndrPackage{{
				importPath: importertest.Project,
				reference:  importertest.V1Rev,
				repository: importertest.ProjectSrc,
			}},
			importertest.TestCase{
				WantSourceRepo: importertest.ProjectSrc,
				WantConstraint: importertest.V1Constraint,
				WantRevision:   importertest.V1Rev,
				WantVersion:    importertest.V1Tag,
			},
		},
		"missing importPath": {
			[]vndrPackage{{
				reference: importertest.V1Tag,
			}},
			importertest.TestCase{
				WantWarning: "Warning: Skipping project. Invalid vndr configuration, import path is required",
			},
		},
		"missing reference": {
			[]vndrPackage{{
				importPath: importertest.Project,
			}},
			importertest.TestCase{
				WantWarning: fmt.Sprintf(
					"Warning: Invalid vndr configuration, reference not found for import path %q",
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
				g.packages = testCase.packages
				return g.convert(importertest.RootProject)
			})
			if err != nil {
				t.Fatalf("%#v", err)
			}
		})
	}
}

func TestVndrConfig_Import(t *testing.T) {
	h := test.NewHelper(t)
	defer h.Cleanup()

	ctx := importertest.NewTestContext(h)
	sm, err := ctx.SourceManager()
	h.Must(err)
	defer sm.Release()

	h.TempDir(filepath.Join("src", importertest.RootProject))
	h.TempCopy(vndrFile(importertest.RootProject), "vendor.conf")
	projectRoot := h.Path(importertest.RootProject)

	logOutput := bytes.NewBuffer(nil)
	ctx.Err = log.New(logOutput, "", 0)

	v := NewImporter(ctx.Err, false, sm)
	if !v.HasDepMetadata(projectRoot) {
		t.Fatal("Expected the importer to detect vndr configuration file")
	}

	m, l, err := v.Import(projectRoot, importertest.RootProject)
	h.Must(err)

	wantM := dep.NewManifest()
	c1, _ := gps.NewSemverConstraint("^0.8.1")
	wantM.Constraints["github.com/sdboyer/deptest"] = gps.ProjectProperties{
		Source:     "https://github.com/sdboyer/deptest.git",
		Constraint: c1,
	}
	c2, _ := gps.NewSemverConstraint("^2.0.0")
	wantM.Constraints["github.com/sdboyer/deptestdos"] = gps.ProjectProperties{
		Constraint: c2,
	}
	if !reflect.DeepEqual(wantM, m) {
		t.Errorf("unexpected manifest\nhave=%+v\nwant=%+v", m, wantM)
	}

	wantL := &dep.Lock{
		P: []gps.LockedProject{
			gps.NewLockedProject(
				gps.ProjectIdentifier{
					ProjectRoot: "github.com/sdboyer/deptest",
					Source:      "https://github.com/sdboyer/deptest.git",
				},
				gps.NewVersion("v0.8.1").Pair("3f4c3bea144e112a69bbe5d8d01c1b09a544253f"),
				nil,
			),
			gps.NewLockedProject(
				gps.ProjectIdentifier{
					ProjectRoot: "github.com/sdboyer/deptestdos",
				},
				gps.NewVersion("v2.0.0").Pair("5c607206be5decd28e6263ffffdcee067266015e"),
				nil,
			),
		},
	}
	if !reflect.DeepEqual(wantL, l) {
		t.Errorf("unexpected lock\nhave=%+v\nwant=%+v", l, wantL)
	}

	goldenFile := "golden.txt"
	got := logOutput.String()
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

func TestParseVndrLine(t *testing.T) {
	testcase := func(in string, wantPkg *vndrPackage, wantErr error) func(*testing.T) {
		return func(t *testing.T) {
			havePkg, haveErr := parseVndrLine(in)
			switch {
			case wantPkg == nil:
				if havePkg != nil {
					t.Errorf("expected nil package, have %v", havePkg)
				}
			case havePkg == nil:
				if wantPkg != nil {
					t.Errorf("expected non-nil package %v, have nil", wantPkg)
				}
			default:
				if !reflect.DeepEqual(havePkg, wantPkg) {
					t.Errorf("unexpected package, have=%v, want=%v", *havePkg, *wantPkg)
				}
			}

			switch {
			case wantErr == nil:
				if haveErr != nil {
					t.Errorf("expected nil err, have %v", haveErr)
				}
			case haveErr == nil:
				if wantErr != nil {
					t.Errorf("expected non-nil err %v, have nil", wantErr)
				}
			default:
				if haveErr.Error() != wantErr.Error() {
					t.Errorf("expected err=%q, have err=%q", wantErr.Error(), haveErr.Error())
				}
			}
		}
	}
	t.Run("normal line",
		testcase("github.com/golang/notreal v1.0.0",
			&vndrPackage{
				importPath: "github.com/golang/notreal",
				reference:  "v1.0.0",
			}, nil))

	t.Run("with repo",
		testcase("github.com/golang/notreal v1.0.0 https://github.com/golang/notreal",
			&vndrPackage{
				importPath: "github.com/golang/notreal",
				reference:  "v1.0.0",
				repository: "https://github.com/golang/notreal",
			}, nil))

	t.Run("trailing comment",
		testcase("github.com/golang/notreal v1.0.0 https://github.com/golang/notreal  # cool comment",
			&vndrPackage{
				importPath: "github.com/golang/notreal",
				reference:  "v1.0.0",
				repository: "https://github.com/golang/notreal",
			}, nil))

	t.Run("empty line", testcase("", nil, nil))
	t.Run("comment line", testcase("# comment", nil, nil))
	t.Run("comment line with leading whitespace", testcase("  # comment", nil, nil))

	t.Run("missing revision",
		testcase("github.com/golang/notreal", nil,
			errors.New("invalid config format: \"github.com/golang/notreal\""),
		))
}
