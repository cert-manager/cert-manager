// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gps

import (
	"reflect"
	"testing"

	"github.com/golang/dep/gps/pkgtree"
)

func TestRootdataExternalImports(t *testing.T) {
	fix := basicFixtures["shared dependency with overlapping constraints"]

	params := SolveParameters{
		RootDir:         string(fix.ds[0].n),
		RootPackageTree: fix.rootTree(),
		Manifest:        fix.rootmanifest(),
		ProjectAnalyzer: naiveAnalyzer{},
		stdLibFn:        func(string) bool { return false },
		mkBridgeFn:      overrideMkBridge,
	}

	is, err := Prepare(params, newdepspecSM(fix.ds, nil))
	if err != nil {
		t.Fatalf("Unexpected error while prepping solver: %s", err)
	}
	rd := is.(*solver).rd

	want := []string{"a", "b"}
	got := rd.externalImportList(params.stdLibFn)
	if !reflect.DeepEqual(want, got) {
		t.Errorf("Unexpected return from rootdata.externalImportList:\n\t(GOT): %s\n\t(WNT): %s", got, want)
	}

	// Add a require
	rd.req["c"] = true

	want = []string{"a", "b", "c"}
	got = rd.externalImportList(params.stdLibFn)
	if !reflect.DeepEqual(want, got) {
		t.Errorf("Unexpected return from rootdata.externalImportList:\n\t(GOT): %s\n\t(WNT): %s", got, want)
	}

	// Add same path as import
	poe := rd.rpt.Packages["root"]
	poe.P.Imports = []string{"a", "b", "c"}
	rd.rpt.Packages["root"] = poe

	// should still be the same
	got = rd.externalImportList(params.stdLibFn)
	if !reflect.DeepEqual(want, got) {
		t.Errorf("Unexpected return from rootdata.externalImportList:\n\t(GOT): %s\n\t(WNT): %s", got, want)
	}

	// Add an ignore, but not on the required path (Prepare makes that
	// combination impossible)

	rd.ir = pkgtree.NewIgnoredRuleset([]string{"b"})
	want = []string{"a", "c"}
	got = rd.externalImportList(params.stdLibFn)
	if !reflect.DeepEqual(want, got) {
		t.Errorf("Unexpected return from rootdata.externalImportList:\n\t(GOT): %s\n\t(WNT): %s", got, want)
	}
}

func TestGetApplicableConstraints(t *testing.T) {
	fix := basicFixtures["shared dependency with overlapping constraints"]

	params := SolveParameters{
		RootDir:         string(fix.ds[0].n),
		RootPackageTree: fix.rootTree(),
		Manifest:        fix.rootmanifest(),
		ProjectAnalyzer: naiveAnalyzer{},
		stdLibFn:        func(string) bool { return false },
		mkBridgeFn:      overrideMkBridge,
	}

	is, err := Prepare(params, newdepspecSM(fix.ds, nil))
	if err != nil {
		t.Fatalf("Unexpected error while prepping solver: %s", err)
	}
	rd := is.(*solver).rd

	table := []struct {
		name   string
		mut    func()
		result []workingConstraint
	}{
		{
			name: "base case, two constraints",
			mut:  func() {},
			result: []workingConstraint{
				{
					Ident:      mkPI("a"),
					Constraint: mkSVC("1.0.0"),
				},
				{
					Ident:      mkPI("b"),
					Constraint: mkSVC("1.0.0"),
				},
			},
		},
		{
			name: "with unconstrained require",
			mut: func() {
				// No constraint means it doesn't show up
				rd.req["c"] = true
			},
			result: []workingConstraint{
				{
					Ident:      mkPI("a"),
					Constraint: mkSVC("1.0.0"),
				},
				{
					Ident:      mkPI("b"),
					Constraint: mkSVC("1.0.0"),
				},
			},
		},
		{
			name: "with unconstrained import",
			mut: func() {
				// Again, no constraint means it doesn't show up
				poe := rd.rpt.Packages["root"]
				poe.P.Imports = []string{"a", "b", "d"}
				rd.rpt.Packages["root"] = poe
			},
			result: []workingConstraint{
				{
					Ident:      mkPI("a"),
					Constraint: mkSVC("1.0.0"),
				},
				{
					Ident:      mkPI("b"),
					Constraint: mkSVC("1.0.0"),
				},
			},
		},
		{
			name: "constraint on required",
			mut: func() {
				rd.rm.Deps["c"] = ProjectProperties{
					Constraint: NewBranch("foo"),
				}
			},
			result: []workingConstraint{
				{
					Ident:      mkPI("a"),
					Constraint: mkSVC("1.0.0"),
				},
				{
					Ident:      mkPI("b"),
					Constraint: mkSVC("1.0.0"),
				},
				{
					Ident:      mkPI("c"),
					Constraint: NewBranch("foo"),
				},
			},
		},
		{
			name: "override on imported",
			mut: func() {
				rd.ovr["d"] = ProjectProperties{
					Constraint: NewBranch("bar"),
				}
			},
			result: []workingConstraint{
				{
					Ident:      mkPI("a"),
					Constraint: mkSVC("1.0.0"),
				},
				{
					Ident:      mkPI("b"),
					Constraint: mkSVC("1.0.0"),
				},
				{
					Ident:      mkPI("c"),
					Constraint: NewBranch("foo"),
				},
				{
					Ident:           mkPI("d"),
					Constraint:      NewBranch("bar"),
					overrConstraint: true,
				},
			},
		},
		{
			// It is certainly the simplest and most rule-abiding solution to
			// drop the constraint in this case, but is there a chance it would
			// violate the principle of least surprise?
			name: "ignore imported and overridden pkg",
			mut: func() {
				rd.ir = pkgtree.NewIgnoredRuleset([]string{"d"})
			},
			result: []workingConstraint{
				{
					Ident:      mkPI("a"),
					Constraint: mkSVC("1.0.0"),
				},
				{
					Ident:      mkPI("b"),
					Constraint: mkSVC("1.0.0"),
				},
				{
					Ident:      mkPI("c"),
					Constraint: NewBranch("foo"),
				},
			},
		},
	}

	for _, fix := range table {
		t.Run(fix.name, func(t *testing.T) {
			fix.mut()

			got := rd.getApplicableConstraints(params.stdLibFn)
			if !reflect.DeepEqual(fix.result, got) {
				t.Errorf("unexpected applicable constraint set:\n\t(GOT): %+v\n\t(WNT): %+v", got, fix.result)
			}
		})
	}
}
