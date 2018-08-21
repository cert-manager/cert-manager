// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dep

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"reflect"
	"strings"
	"testing"

	"github.com/golang/dep/gps"
	"github.com/golang/dep/internal/test"
)

func TestReadManifest(t *testing.T) {
	h := test.NewHelper(t)
	defer h.Cleanup()

	mf := h.GetTestFile("manifest/golden.toml")
	defer mf.Close()
	got, _, err := readManifest(mf)
	if err != nil {
		t.Fatalf("should have read manifest correctly, but got err %q", err)
	}

	c, _ := gps.NewSemverConstraint("^0.12.0")
	want := Manifest{
		Constraints: map[gps.ProjectRoot]gps.ProjectProperties{
			gps.ProjectRoot("github.com/golang/dep"): {
				Constraint: c,
			},
			gps.ProjectRoot("github.com/babble/brook"): {
				Constraint: gps.Revision("d05d5aca9f895d19e9265839bffeadd74a2d2ecb"),
			},
		},
		Ovr: map[gps.ProjectRoot]gps.ProjectProperties{
			gps.ProjectRoot("github.com/golang/dep"): {
				Source:     "https://github.com/golang/dep",
				Constraint: gps.NewBranch("master"),
			},
		},
		Ignored: []string{"github.com/foo/bar"},
		PruneOptions: gps.CascadingPruneOptions{
			DefaultOptions:    gps.PruneNestedVendorDirs | gps.PruneNonGoFiles,
			PerProjectOptions: make(map[gps.ProjectRoot]gps.PruneOptionSet),
		},
	}

	if !reflect.DeepEqual(got.Constraints, want.Constraints) {
		t.Error("Valid manifest's dependencies did not parse as expected")
	}
	if !reflect.DeepEqual(got.Ovr, want.Ovr) {
		t.Error("Valid manifest's overrides did not parse as expected")
	}
	if !reflect.DeepEqual(got.Ignored, want.Ignored) {
		t.Error("Valid manifest's ignored did not parse as expected")
	}
	if !reflect.DeepEqual(got.PruneOptions, want.PruneOptions) {
		t.Error("Valid manifest's prune options did not parse as expected")
		t.Error(got.PruneOptions, want.PruneOptions)
	}
}

func TestWriteManifest(t *testing.T) {
	h := test.NewHelper(t)
	defer h.Cleanup()

	golden := "manifest/golden.toml"
	want := h.GetTestFileString(golden)
	c, _ := gps.NewSemverConstraint("^0.12.0")
	m := NewManifest()
	m.Constraints[gps.ProjectRoot("github.com/golang/dep")] = gps.ProjectProperties{
		Constraint: c,
	}
	m.Constraints[gps.ProjectRoot("github.com/babble/brook")] = gps.ProjectProperties{
		Constraint: gps.Revision("d05d5aca9f895d19e9265839bffeadd74a2d2ecb"),
	}
	m.Ovr[gps.ProjectRoot("github.com/golang/dep")] = gps.ProjectProperties{
		Source:     "https://github.com/golang/dep",
		Constraint: gps.NewBranch("master"),
	}
	m.Ignored = []string{"github.com/foo/bar"}
	m.PruneOptions = gps.CascadingPruneOptions{
		DefaultOptions:    gps.PruneNestedVendorDirs | gps.PruneNonGoFiles,
		PerProjectOptions: make(map[gps.ProjectRoot]gps.PruneOptionSet),
	}

	got, err := m.MarshalTOML()
	if err != nil {
		t.Fatalf("error while marshaling valid manifest to TOML: %q", err)
	}

	if string(got) != want {
		if *test.UpdateGolden {
			if err = h.WriteTestFile(golden, string(got)); err != nil {
				t.Fatal(err)
			}
		} else {
			t.Errorf("valid manifest did not marshal to TOML as expected:\n(GOT):\n%s\n(WNT):\n%s", string(got), want)
		}
	}
}

func TestReadManifestErrors(t *testing.T) {
	h := test.NewHelper(t)
	defer h.Cleanup()
	var err error

	tests := []struct {
		name string
		file string
	}{
		{"multiple constraints", "manifest/error1.toml"},
		{"multiple dependencies", "manifest/error2.toml"},
		{"multiple overrides", "manifest/error3.toml"},
	}

	for _, tst := range tests {
		mf := h.GetTestFile(tst.file)
		defer mf.Close()
		_, _, err = readManifest(mf)
		if err == nil {
			t.Errorf("reading manifest with %s should have caused error, but did not", tst.name)
		} else if !strings.Contains(err.Error(), tst.name) {
			t.Errorf("unexpected error %q; expected %s error", err, tst.name)
		}
	}
}

func TestValidateManifest(t *testing.T) {
	cases := []struct {
		name       string
		tomlString string
		wantWarn   []error
		wantError  error
	}{
		{
			name: "valid required",
			tomlString: `
			required = ["github.com/foo/bar"]
			`,
			wantWarn:  []error{},
			wantError: nil,
		},
		{
			name: "invalid required",
			tomlString: `
			required = "github.com/foo/bar"
			`,
			wantWarn:  []error{},
			wantError: errInvalidRequired,
		},
		{
			name: "empty required",
			tomlString: `
			required = []
			`,
			wantWarn:  []error{},
			wantError: nil,
		},
		{
			name: "invalid required list",
			tomlString: `
			required = [1, 2, 3]
			`,
			wantWarn:  []error{},
			wantError: errInvalidRequired,
		},
		{
			name: "invalid required format",
			tomlString: `
			[[required]]
			  name = "foo"
			`,
			wantWarn:  []error{},
			wantError: errInvalidRequired,
		},
		{
			name: "valid ignored",
			tomlString: `
			ignored = ["foo"]
			`,
			wantWarn:  []error{},
			wantError: nil,
		},
		{
			name: "invalid ignored",
			tomlString: `
			ignored = "foo"
			`,
			wantWarn:  []error{},
			wantError: errInvalidIgnored,
		},
		{
			name: "empty ignored",
			tomlString: `
			ignored = []
			`,
			wantWarn:  []error{},
			wantError: nil,
		},
		{
			name: "invalid ignored list",
			tomlString: `
			ignored = [1, 2, 3]
			`,
			wantWarn:  []error{},
			wantError: errInvalidIgnored,
		},
		{
			name: "invalid ignored format",
			tomlString: `
			[[ignored]]
			  name = "foo"
			`,
			wantWarn:  []error{},
			wantError: errInvalidIgnored,
		},
		{
			name: "valid metadata",
			tomlString: `
			[metadata]
			  authors = "foo"
			  version = "1.0.0"
			`,
			wantWarn:  []error{},
			wantError: nil,
		},
		{
			name: "invalid metadata",
			tomlString: `
			foo = "some-value"
			version = 14

			[[bar]]
			  author = "xyz"

			[[constraint]]
			  name = "github.com/foo/bar"
			  version = ""
			`,
			wantWarn: []error{
				errors.New("unknown field in manifest: foo"),
				errors.New("unknown field in manifest: bar"),
				errors.New("unknown field in manifest: version"),
			},
			wantError: nil,
		},
		{
			name: "invalid metadata format",
			tomlString: `
			metadata = "project-name"

			[[constraint]]
			  name = "github.com/foo/bar"
			`,
			wantWarn: []error{
				errInvalidMetadata,
				errors.New("branch, version, revision, or source should be provided for \"github.com/foo/bar\""),
			},
			wantError: nil,
		},
		{
			name: "plain constraint",
			tomlString: `
			[[constraint]]
			  name = "github.com/foo/bar"
			`,
			wantWarn: []error{
				errors.New("branch, version, revision, or source should be provided for \"github.com/foo/bar\""),
			},
			wantError: nil,
		},
		{
			name: "empty constraint",
			tomlString: `
			[[constraint]]
			`,
			wantWarn: []error{
				errNoName,
			},
			wantError: nil,
		},
		{
			name: "invalid constraint",
			tomlString: `
			constraint = "foo"
			`,
			wantWarn:  []error{},
			wantError: errInvalidConstraint,
		},
		{
			name: "invalid constraint list",
			tomlString: `
			constraint = ["foo", "bar"]
			`,
			wantWarn:  []error{},
			wantError: errInvalidConstraint,
		},
		{
			name: "valid override",
			tomlString: `
			[[override]]
			  name = "github.com/foo/bar"
			`,
			wantWarn:  []error{},
			wantError: nil,
		},
		{
			name: "empty override",
			tomlString: `
			[[override]]
			`,
			wantWarn: []error{
				errNoName,
			},
			wantError: nil,
		},
		{
			name: "invalid override",
			tomlString: `
			override = "bar"
			`,
			wantWarn:  []error{},
			wantError: errInvalidOverride,
		},
		{
			name: "invalid override list",
			tomlString: `
			override = ["foo", "bar"]
			`,
			wantWarn:  []error{},
			wantError: errInvalidOverride,
		},
		{
			name: "invalid fields",
			tomlString: `
			[[constraint]]
			  name = "github.com/foo/bar"
			  location = "some-value"
			  link = "some-other-value"
			  metadata = "foo"

			[[override]]
			  nick = "foo"
			`,
			wantWarn: []error{
				errors.New("invalid key \"location\" in \"constraint\""),
				errors.New("invalid key \"link\" in \"constraint\""),
				errors.New("metadata in \"constraint\" should be a TOML table"),
				errors.New("branch, version, revision, or source should be provided for \"github.com/foo/bar\""),
				errors.New("invalid key \"nick\" in \"override\""),
				errNoName,
			},
			wantError: nil,
		},
		{
			name: "constraint metadata",
			tomlString: `
			[[constraint]]
			  name = "github.com/foo/bar"

			  [constraint.metadata]
			    color = "blue"
			`,
			wantWarn: []error{
				errors.New("branch, version, revision, or source should be provided for \"github.com/foo/bar\""),
			},
			wantError: nil,
		},
		{
			name: "invalid revision",
			tomlString: `
			[[constraint]]
			  name = "github.com/foo/bar"
			  revision = "b86ad16"
			`,
			wantWarn: []error{
				errors.New("revision \"b86ad16\" should not be in abbreviated form"),
			},
			wantError: nil,
		},
		{
			name: "invalid hg revision",
			tomlString: `
			[[constraint]]
			  name = "foobar.com/hg"
			  revision = "8d43f8c0b836"
			`,
			wantWarn:  []error{errors.New("revision \"8d43f8c0b836\" should not be in abbreviated form")},
			wantError: nil,
		},
		{
			name: "valid prune options",
			tomlString: `
			[prune]
			  non-go = true
			`,
			wantWarn:  []error{},
			wantError: nil,
		},
		{
			name: "invalid root prune options",
			tomlString: `
			[prune]
			  non-go = false
			`,
			wantWarn:  []error{},
			wantError: errInvalidRootPruneValue,
		},
		{
			name: "root options should not contain a name",
			tomlString: `
			[prune]
			  go-tests = true
			  name = "github.com/golang/dep"
			`,
			wantWarn: []error{
				errRootPruneContainsName,
			},
			wantError: nil,
		},
		{
			name: "invalid prune project",
			tomlString: `
			[prune]
			  non-go = true

			  [prune.project]
			    name = "github.com/org/project"
			    non-go = true
			`,
			wantWarn:  []error{},
			wantError: errInvalidPruneProject,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			errs, err := validateManifest(c.tomlString)

			// compare validation errors
			if err != c.wantError {
				t.Fatalf("manifest errors are not as expected: \n\t(GOT) %v \n\t(WNT) %v", err, c.wantError)
			}

			// compare length of error slice
			if len(errs) != len(c.wantWarn) {
				t.Fatalf("number of manifest errors are not as expected: \n\t(GOT) %v errors(%v)\n\t(WNT) %v errors(%v).", len(errs), errs, len(c.wantWarn), c.wantWarn)
			}

			// check if the expected errors exist in actual errors slice
			for _, er := range errs {
				if !containsErr(c.wantWarn, er) {
					t.Fatalf("manifest errors are not as expected: \n\t(MISSING) %v\n\t(FROM) %v", er, c.wantWarn)
				}
			}
		})
	}
}

func TestCheckRedundantPruneOptions(t *testing.T) {
	cases := []struct {
		name         string
		pruneOptions gps.CascadingPruneOptions
		wantWarn     []error
	}{
		{
			name: "all redundant on true",
			pruneOptions: gps.CascadingPruneOptions{
				DefaultOptions: 15,
				PerProjectOptions: map[gps.ProjectRoot]gps.PruneOptionSet{
					"github.com/golang/dep": {
						NestedVendor:   pvtrue,
						UnusedPackages: pvtrue,
						NonGoFiles:     pvtrue,
						GoTests:        pvtrue,
					},
				},
			},
			wantWarn: []error{
				fmt.Errorf("redundant prune option %q set for %q", "unused-packages", "github.com/golang/dep"),
				fmt.Errorf("redundant prune option %q set for %q", "non-go", "github.com/golang/dep"),
				fmt.Errorf("redundant prune option %q set for %q", "go-tests", "github.com/golang/dep"),
			},
		},
		{
			name: "all redundant on false",
			pruneOptions: gps.CascadingPruneOptions{
				DefaultOptions: 1,
				PerProjectOptions: map[gps.ProjectRoot]gps.PruneOptionSet{
					"github.com/golang/dep": {
						NestedVendor:   pvtrue,
						UnusedPackages: pvfalse,
						NonGoFiles:     pvfalse,
						GoTests:        pvfalse,
					},
				},
			},
			wantWarn: []error{
				fmt.Errorf("redundant prune option %q set for %q", "unused-packages", "github.com/golang/dep"),
				fmt.Errorf("redundant prune option %q set for %q", "non-go", "github.com/golang/dep"),
				fmt.Errorf("redundant prune option %q set for %q", "go-tests", "github.com/golang/dep"),
			},
		},
		{
			name: "redundancy mix across multiple projects",
			pruneOptions: gps.CascadingPruneOptions{
				DefaultOptions: 7,
				PerProjectOptions: map[gps.ProjectRoot]gps.PruneOptionSet{
					"github.com/golang/dep": {
						NestedVendor: pvtrue,
						NonGoFiles:   pvtrue,
						GoTests:      pvtrue,
					},
					"github.com/other/project": {
						NestedVendor:   pvtrue,
						UnusedPackages: pvfalse,
						GoTests:        pvfalse,
					},
				},
			},
			wantWarn: []error{
				fmt.Errorf("redundant prune option %q set for %q", "non-go", "github.com/golang/dep"),
				fmt.Errorf("redundant prune option %q set for %q", "go-tests", "github.com/other/project"),
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			errs := checkRedundantPruneOptions(c.pruneOptions)

			// compare length of error slice
			if len(errs) != len(c.wantWarn) {
				t.Fatalf("number of manifest errors are not as expected:\n\t(GOT) %v errors(%v)\n\t(WNT) %v errors(%v).", len(errs), errs, len(c.wantWarn), c.wantWarn)
			}

			for _, er := range errs {
				if !containsErr(c.wantWarn, er) {
					t.Fatalf("manifest errors are not as expected:\n\t(MISSING)\n%v\n\t(FROM)\n%v", er, c.wantWarn)
				}
			}
		})
	}
}

func TestValidateProjectRoots(t *testing.T) {
	cases := []struct {
		name      string
		manifest  Manifest
		wantError error
		wantWarn  []string
	}{
		{
			name:      "empty Manifest",
			manifest:  Manifest{},
			wantError: nil,
			wantWarn:  []string{},
		},
		{
			name: "valid project root",
			manifest: Manifest{
				Constraints: map[gps.ProjectRoot]gps.ProjectProperties{
					gps.ProjectRoot("github.com/golang/dep"): {
						Constraint: gps.Any(),
					},
				},
			},
			wantError: nil,
			wantWarn:  []string{},
		},
		{
			name: "invalid project roots in Constraints and Overrides",
			manifest: Manifest{
				Constraints: map[gps.ProjectRoot]gps.ProjectProperties{
					gps.ProjectRoot("github.com/golang/dep/foo"): {
						Constraint: gps.Any(),
					},
					gps.ProjectRoot("github.com/golang/go/xyz"): {
						Constraint: gps.Any(),
					},
					gps.ProjectRoot("github.com/golang/fmt"): {
						Constraint: gps.Any(),
					},
				},
				Ovr: map[gps.ProjectRoot]gps.ProjectProperties{
					gps.ProjectRoot("github.com/golang/mock/bar"): {
						Constraint: gps.Any(),
					},
					gps.ProjectRoot("github.com/golang/mock"): {
						Constraint: gps.Any(),
					},
				},
			},
			wantError: errInvalidProjectRoot,
			wantWarn: []string{
				"the name for \"github.com/golang/dep/foo\" should be changed to \"github.com/golang/dep\"",
				"the name for \"github.com/golang/mock/bar\" should be changed to \"github.com/golang/mock\"",
				"the name for \"github.com/golang/go/xyz\" should be changed to \"github.com/golang/go\"",
			},
		},
		{
			name: "invalid source path",
			manifest: Manifest{
				Constraints: map[gps.ProjectRoot]gps.ProjectProperties{
					gps.ProjectRoot("github.com/golang"): {
						Constraint: gps.Any(),
					},
				},
			},
			wantError: errInvalidProjectRoot,
			wantWarn:  []string{},
		},
	}

	h := test.NewHelper(t)
	defer h.Cleanup()

	h.TempDir("src")
	pwd := h.Path(".")

	// Capture the stderr to verify the warnings
	stderrOutput := &bytes.Buffer{}
	errLogger := log.New(stderrOutput, "", 0)
	ctx := &Ctx{
		GOPATH: pwd,
		Out:    log.New(ioutil.Discard, "", 0),
		Err:    errLogger,
	}

	sm, err := ctx.SourceManager()
	h.Must(err)
	defer sm.Release()

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Empty the buffer for every case
			stderrOutput.Reset()
			err := ValidateProjectRoots(ctx, &c.manifest, sm)
			if err != c.wantError {
				t.Fatalf("unexpected error while validating project roots:\n\t(GOT): %v\n\t(WNT): %v", err, c.wantError)
			}

			warnings := stderrOutput.String()
			for _, warn := range c.wantWarn {
				if !strings.Contains(warnings, warn) {
					t.Fatalf("expected ValidateProjectRoot errors to contain: %q", warn)
				}
			}
		})
	}
}

//func TestFromRawPruneOptions(t *testing.T) {
//cases := []struct {
//name            string
//rawPruneOptions rawPruneOptions
//wantOptions     gps.CascadingPruneOptions
//}{
//{
//name: "global all options project no options",
//rawPruneOptions: rawPruneOptions{
//UnusedPackages: true,
//NonGoFiles:     true,
//GoTests:        true,
//Projects: []map[string]interface{}{
//{
//"name": "github.com/golang/dep",
//pruneOptionUnusedPackages: false,
//pruneOptionNonGo:          false,
//pruneOptionGoTests:        false,
//},
//},
//},
//wantOptions: gps.CascadingPruneOptions{
//DefaultOptions: 15,
//PerProjectOptions: map[gps.ProjectRoot]gps.PruneOptionSet{
//"github.com/golang/dep": gps.PruneOptionSet{
//NestedVendor:   pvtrue,
//UnusedPackages: pvfalse,
//NonGoFiles:     pvfalse,
//GoTests:        pvfalse,
//},
//},
//},
//},
//{
//name: "global all options project mixed options",
//rawPruneOptions: rawPruneOptions{
//UnusedPackages: true,
//NonGoFiles:     true,
//GoTests:        true,
//Projects: []map[string]interface{}{
//{
//"name": "github.com/golang/dep",
//pruneOptionUnusedPackages: false,
//},
//},
//},
//wantOptions: gps.CascadingPruneOptions{
//DefaultOptions: 15,
//PerProjectOptions: map[gps.ProjectRoot]gps.PruneOptionSet{
//"github.com/golang/dep": gps.PruneOptionSet{
//NestedVendor:   pvtrue,
//UnusedPackages: pvfalse,
//},
//},
//},
//},
//{
//name: "global no options project all options",
//rawPruneOptions: rawPruneOptions{
//UnusedPackages: false,
//NonGoFiles:     false,
//GoTests:        false,
//Projects: []map[string]interface{}{
//{
//"name": "github.com/golang/dep",
//pruneOptionUnusedPackages: true,
//pruneOptionNonGo:          true,
//pruneOptionGoTests:        true,
//},
//},
//},
//wantOptions: gps.CascadingPruneOptions{
//DefaultOptions: 1,
//PerProjectOptions: map[gps.ProjectRoot]gps.PruneOptionSet{
//"github.com/golang/dep": gps.PruneOptionSet{
//NestedVendor:   pvtrue,
//UnusedPackages: pvtrue,
//NonGoFiles:     pvtrue,
//GoTests:        pvtrue,
//},
//},
//},
//},
//}

//for _, c := range cases {
//t.Run(c.name, func(t *testing.T) {
//opts, err := fromRawPruneOptions(c.rawPruneOptions)
//if err != nil {
//t.Fatal(err)
//}

//if !reflect.DeepEqual(opts, c.wantOptions) {
//t.Fatalf("rawPruneOptions are not as expected:\n\t(GOT) %v\n\t(WNT) %v", opts, c.wantOptions)
//}
//})
//}
//}

func TestToRawPruneOptions(t *testing.T) {
	cases := []struct {
		name         string
		pruneOptions gps.CascadingPruneOptions
		wantOptions  rawPruneOptions
	}{
		{
			name:         "all options",
			pruneOptions: gps.CascadingPruneOptions{DefaultOptions: 15},
			wantOptions: rawPruneOptions{
				UnusedPackages: true,
				NonGoFiles:     true,
				GoTests:        true,
			},
		},
		{
			name:         "no options",
			pruneOptions: gps.CascadingPruneOptions{DefaultOptions: 1},
			wantOptions: rawPruneOptions{
				UnusedPackages: false,
				NonGoFiles:     false,
				GoTests:        false,
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			raw := toRawPruneOptions(c.pruneOptions)

			if !reflect.DeepEqual(raw, c.wantOptions) {
				t.Fatalf("rawPruneOptions are not as expected:\n\t(GOT) %v\n\t(WNT) %v", raw, c.wantOptions)
			}
		})
	}
}

func TestToRawPruneOptions_Panic(t *testing.T) {
	pruneOptions := gps.CascadingPruneOptions{
		DefaultOptions: 1,
		PerProjectOptions: map[gps.ProjectRoot]gps.PruneOptionSet{
			"github.com/carolynvs/deptest": {
				NestedVendor: pvtrue,
			},
		},
	}
	defer func() {
		if err := recover(); err == nil {
			t.Error("toRawPruneOptions did not panic with non-empty ProjectOptions")
		}
	}()
	_ = toRawPruneOptions(pruneOptions)
}

func containsErr(s []error, e error) bool {
	for _, a := range s {
		if a.Error() == e.Error() {
			return true
		}
	}
	return false
}
