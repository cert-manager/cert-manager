// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"errors"
	"go/build"
	"io/ioutil"
	"log"
	"strings"
	"testing"

	"github.com/golang/dep"
	"github.com/golang/dep/gps"
	"github.com/golang/dep/gps/pkgtree"
	"github.com/golang/dep/internal/test"
)

func TestInvalidEnsureFlagCombinations(t *testing.T) {
	ec := &ensureCommand{
		update: true,
		add:    true,
	}

	if err := ec.validateFlags(); err == nil {
		t.Error("-add and -update together should fail validation")
	}

	ec.vendorOnly, ec.add = true, false
	if err := ec.validateFlags(); err == nil {
		t.Error("-vendor-only with -update should fail validation")
	}

	ec.add, ec.update = true, false
	if err := ec.validateFlags(); err == nil {
		t.Error("-vendor-only with -add should fail validation")
	}

	ec.noVendor, ec.add = true, false
	if err := ec.validateFlags(); err == nil {
		t.Error("-vendor-only with -no-vendor should fail validation")
	}
	ec.noVendor = false

	// Also verify that the plain ensure path takes no args. This is a shady
	// test, as lots of other things COULD return errors, and we don't check
	// anything other than the error being non-nil. For now, it works well
	// because a panic will quickly result if the initial arg length validation
	// checks are incorrectly handled.
	if err := ec.runDefault(nil, []string{"foo"}, nil, nil, gps.SolveParameters{}); err == nil {
		t.Errorf("no args to plain ensure with -vendor-only")
	}
	ec.vendorOnly = false
	if err := ec.runDefault(nil, []string{"foo"}, nil, nil, gps.SolveParameters{}); err == nil {
		t.Errorf("no args to plain ensure")
	}
}

func TestCheckErrors(t *testing.T) {
	tt := []struct {
		name        string
		fatal       bool
		pkgOrErrMap map[string]pkgtree.PackageOrErr
	}{
		{
			name:  "noErrors",
			fatal: false,
			pkgOrErrMap: map[string]pkgtree.PackageOrErr{
				"mypkg": {
					P: pkgtree.Package{},
				},
			},
		},
		{
			name:  "hasErrors",
			fatal: true,
			pkgOrErrMap: map[string]pkgtree.PackageOrErr{
				"github.com/me/pkg": {
					Err: &build.NoGoError{},
				},
				"github.com/someone/pkg": {
					Err: errors.New("code is busted"),
				},
			},
		},
		{
			name:  "onlyGoErrors",
			fatal: false,
			pkgOrErrMap: map[string]pkgtree.PackageOrErr{
				"github.com/me/pkg": {
					Err: &build.NoGoError{},
				},
				"github.com/someone/pkg": {
					P: pkgtree.Package{},
				},
			},
		},
		{
			name:  "onlyBuildErrors",
			fatal: false,
			pkgOrErrMap: map[string]pkgtree.PackageOrErr{
				"github.com/me/pkg": {
					Err: &build.NoGoError{},
				},
				"github.com/someone/pkg": {
					P: pkgtree.Package{},
				},
			},
		},
		{
			name:  "allGoErrors",
			fatal: true,
			pkgOrErrMap: map[string]pkgtree.PackageOrErr{
				"github.com/me/pkg": {
					Err: &build.NoGoError{},
				},
			},
		},
		{
			name:  "allMixedErrors",
			fatal: true,
			pkgOrErrMap: map[string]pkgtree.PackageOrErr{
				"github.com/me/pkg": {
					Err: &build.NoGoError{},
				},
				"github.com/someone/pkg": {
					Err: errors.New("code is busted"),
				},
			},
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			fatal, err := checkErrors(tc.pkgOrErrMap, nil)
			if tc.fatal != fatal {
				t.Fatalf("expected fatal flag to be %T, got %T", tc.fatal, fatal)
			}
			if err == nil && fatal {
				t.Fatal("unexpected fatal flag value while err is nil")
			}
		})
	}
}

func TestValidateUpdateArgs(t *testing.T) {
	cases := []struct {
		name           string
		args           []string
		wantError      error
		wantWarn       []string
		lockedProjects []string
	}{
		{
			name:      "empty args",
			args:      []string{},
			wantError: nil,
		},
		{
			name:      "not project root",
			args:      []string{"github.com/golang/dep/cmd"},
			wantError: errUpdateArgsValidation,
			wantWarn: []string{
				"github.com/golang/dep/cmd is not a project root, try github.com/golang/dep instead",
			},
		},
		{
			name:      "not present in lock",
			args:      []string{"github.com/golang/dep"},
			wantError: errUpdateArgsValidation,
			wantWarn: []string{
				"github.com/golang/dep is not present in Gopkg.lock, cannot -update it",
			},
		},
		{
			name:      "cannot specify alternate sources",
			args:      []string{"github.com/golang/dep:github.com/example/dep"},
			wantError: errUpdateArgsValidation,
			wantWarn: []string{
				"cannot specify alternate sources on -update (github.com/example/dep)",
			},
			lockedProjects: []string{"github.com/golang/dep"},
		},
		{
			name:      "version constraint passed",
			args:      []string{"github.com/golang/dep@master"},
			wantError: errUpdateArgsValidation,
			wantWarn: []string{
				"version constraint master passed for github.com/golang/dep, but -update follows constraints declared in Gopkg.toml, not CLI arguments",
			},
			lockedProjects: []string{"github.com/golang/dep"},
		},
		{
			name:      "flags after spec",
			args:      []string{"github.com/golang/dep@master", "-v"},
			wantError: errUpdateArgsValidation,
			wantWarn: []string{
				"could not infer project root from dependency path",
			},
			lockedProjects: []string{"github.com/golang/dep"},
		},
	}

	h := test.NewHelper(t)
	defer h.Cleanup()

	h.TempDir("src")
	pwd := h.Path(".")

	stderrOutput := &bytes.Buffer{}
	errLogger := log.New(stderrOutput, "", 0)
	ctx := &dep.Ctx{
		GOPATH: pwd,
		Out:    log.New(ioutil.Discard, "", 0),
		Err:    errLogger,
	}

	sm, err := ctx.SourceManager()
	h.Must(err)
	defer sm.Release()

	p := new(dep.Project)
	params := p.MakeParams()

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// Empty the buffer for every case
			stderrOutput.Reset()

			// Fill up the locked projects
			lockedProjects := make([]gps.LockedProject, 0, len(c.lockedProjects))
			for _, lp := range c.lockedProjects {
				pi := gps.ProjectIdentifier{ProjectRoot: gps.ProjectRoot(lp)}
				lockedProjects = append(lockedProjects, gps.NewLockedProject(pi, gps.NewVersion("v1.0.0"), []string{}))
			}

			// Add lock to project
			p.Lock = &dep.Lock{P: lockedProjects}

			err := validateUpdateArgs(ctx, c.args, p, sm, &params)
			if err != c.wantError {
				t.Fatalf("Unexpected error while validating update args:\n\t(GOT): %v\n\t(WNT): %v", err, c.wantError)
			}

			warnings := stderrOutput.String()
			for _, warn := range c.wantWarn {
				if !strings.Contains(warnings, warn) {
					t.Fatalf("Expected validateUpdateArgs errors to contain: %q", warn)
				}
			}
		})
	}
}
