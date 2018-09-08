// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gps

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/golang/dep/gps/pkgtree"
)

// dsp - "depspec with packages"
//
// Wraps a set of tpkgs onto a depspec, and returns it.
func dsp(ds depspec, pkgs ...tpkg) depspec {
	ds.pkgs = pkgs
	return ds
}

// pkg makes a tpkg appropriate for use in bimodal testing
func pkg(path string, imports ...string) tpkg {
	return tpkg{
		path:    path,
		imports: imports,
	}
}

func init() {
	for k, fix := range bimodalFixtures {
		// Assign the name into the fixture itself
		fix.n = k
		bimodalFixtures[k] = fix
	}
}

// Fixtures that rely on simulated bimodal (project and package-level)
// analysis for correct operation. The name given in the map gets assigned into
// the fixture itself in init().
var bimodalFixtures = map[string]bimodalFixture{
	// Simple case, ensures that we do the very basics of picking up and
	// including a single, simple import that is not expressed as a constraint
	"simple bm-add": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0"),
				pkg("root", "a")),
			dsp(mkDepspec("a 1.0.0"),
				pkg("a")),
		},
		r: mksolution(
			"a 1.0.0",
		),
	},
	// Ensure it works when the import jump is not from the package with the
	// same path as root, but from a subpkg
	"subpkg bm-add": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0"),
				pkg("root", "root/foo"),
				pkg("root/foo", "a"),
			),
			dsp(mkDepspec("a 1.0.0"),
				pkg("a"),
			),
		},
		r: mksolution(
			"a 1.0.0",
		),
	},
	// The same, but with a jump through two subpkgs
	"double-subpkg bm-add": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0"),
				pkg("root", "root/foo"),
				pkg("root/foo", "root/bar"),
				pkg("root/bar", "a"),
			),
			dsp(mkDepspec("a 1.0.0"),
				pkg("a"),
			),
		},
		r: mksolution(
			"a 1.0.0",
		),
	},
	// Same again, but now nest the subpkgs
	"double nested subpkg bm-add": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0"),
				pkg("root", "root/foo"),
				pkg("root/foo", "root/foo/bar"),
				pkg("root/foo/bar", "a"),
			),
			dsp(mkDepspec("a 1.0.0"),
				pkg("a"),
			),
		},
		r: mksolution(
			"a 1.0.0",
		),
	},
	// Importing package from project with no root package
	"bm-add on project with no pkg in root dir": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0"),
				pkg("root", "a/foo")),
			dsp(mkDepspec("a 1.0.0"),
				pkg("a/foo")),
		},
		r: mksolution(
			mklp("a 1.0.0", "foo"),
		),
	},
	// Import jump is in a dep, and points to a transitive dep
	"transitive bm-add": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0"),
				pkg("root", "root/foo"),
				pkg("root/foo", "a"),
			),
			dsp(mkDepspec("a 1.0.0"),
				pkg("a", "b"),
			),
			dsp(mkDepspec("b 1.0.0"),
				pkg("b"),
			),
		},
		r: mksolution(
			"a 1.0.0",
			"b 1.0.0",
		),
	},
	// Constraints apply only if the project that declares them has a
	// reachable import
	"constraints activated by import": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0", "b 1.0.0"),
				pkg("root", "root/foo"),
				pkg("root/foo", "a"),
			),
			dsp(mkDepspec("a 1.0.0"),
				pkg("a", "b"),
			),
			dsp(mkDepspec("b 1.0.0"),
				pkg("b"),
			),
			dsp(mkDepspec("b 1.1.0"),
				pkg("b"),
			),
		},
		r: mksolution(
			"a 1.0.0",
			"b 1.1.0",
		),
	},
	// Constraints apply only if the project that declares them has a
	// reachable import - non-root
	"constraints activated by import, transitive": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0"),
				pkg("root", "root/foo", "b"),
				pkg("root/foo", "a"),
			),
			dsp(mkDepspec("a 1.0.0", "b 1.0.0"),
				pkg("a"),
			),
			dsp(mkDepspec("b 1.0.0"),
				pkg("b"),
			),
			dsp(mkDepspec("b 1.1.0"),
				pkg("b"),
			),
		},
		r: mksolution(
			"a 1.0.0",
			"b 1.1.0",
		),
	},
	// Import jump is in a dep, and points to a transitive dep - but only in not
	// the first version we try
	"transitive bm-add on older version": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0", "a ~1.0.0"),
				pkg("root", "root/foo"),
				pkg("root/foo", "a"),
			),
			dsp(mkDepspec("a 1.0.0"),
				pkg("a", "b"),
			),
			dsp(mkDepspec("a 1.1.0"),
				pkg("a"),
			),
			dsp(mkDepspec("b 1.0.0"),
				pkg("b"),
			),
		},
		r: mksolution(
			"a 1.0.0",
			"b 1.0.0",
		),
	},
	// Import jump is in a dep, and points to a transitive dep - but will only
	// get there via backtracking
	"backtrack to dep on bm-add": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0"),
				pkg("root", "root/foo"),
				pkg("root/foo", "a", "b"),
			),
			dsp(mkDepspec("a 1.0.0"),
				pkg("a", "c"),
			),
			dsp(mkDepspec("a 1.1.0"),
				pkg("a"),
			),
			// Include two versions of b, otherwise it'll be selected first
			dsp(mkDepspec("b 0.9.0"),
				pkg("b", "c"),
			),
			dsp(mkDepspec("b 1.0.0"),
				pkg("b", "c"),
			),
			dsp(mkDepspec("c 1.0.0", "a 1.0.0"),
				pkg("c", "a"),
			),
		},
		r: mksolution(
			"a 1.0.0",
			"b 1.0.0",
			"c 1.0.0",
		),
	},
	"backjump through pkg-only selection": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0"),
				pkg("root", "root/foo"),
				pkg("root/foo", "a", "b"),
			),
			dsp(mkDepspec("a 1.0.0"),
				pkg("a", "c"),
			),
			// Include two versions of b to ensure that a is visited first
			dsp(mkDepspec("b 0.9.0", "d ^1.0.0"),
				pkg("b", "c/other", "d"),
			),
			dsp(mkDepspec("b 1.0.0", "d ^1.2.0"),
				pkg("b", "c/other", "d"),
			),
			// Three versions of c so it's last
			dsp(mkDepspec("c 1.0.0", "d ^1.0.0"),
				pkg("c", "d"),
				pkg("c/other"),
			),
			dsp(mkDepspec("d 1.0.0"),
				pkg("d"),
			),
			dsp(mkDepspec("d 1.1.0"),
				pkg("d"),
			),
		},
		r: mksolution(
			"a 1.0.0",
			"b 0.9.0",
			mklp("c 1.0.0", ".", "other"),
			"d 1.1.0",
		),
	},
	// Import jump is in a dep subpkg, and points to a transitive dep
	"transitive subpkg bm-add": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0"),
				pkg("root", "root/foo"),
				pkg("root/foo", "a"),
			),
			dsp(mkDepspec("a 1.0.0"),
				pkg("a", "a/bar"),
				pkg("a/bar", "b"),
			),
			dsp(mkDepspec("b 1.0.0"),
				pkg("b"),
			),
		},
		r: mksolution(
			mklp("a 1.0.0", ".", "bar"),
			"b 1.0.0",
		),
	},
	// Import jump is in a dep subpkg, pointing to a transitive dep, but only in
	// not the first version we try
	"transitive subpkg bm-add on older version": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0", "a ~1.0.0"),
				pkg("root", "root/foo"),
				pkg("root/foo", "a"),
			),
			dsp(mkDepspec("a 1.0.0"),
				pkg("a", "a/bar"),
				pkg("a/bar", "b"),
			),
			dsp(mkDepspec("a 1.1.0"),
				pkg("a", "a/bar"),
				pkg("a/bar"),
			),
			dsp(mkDepspec("b 1.0.0"),
				pkg("b"),
			),
		},
		r: mksolution(
			mklp("a 1.0.0", ".", "bar"),
			"b 1.0.0",
		),
	},
	"project cycle involving root": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0", "a ~1.0.0"),
				pkg("root", "a"),
				pkg("root/foo"),
			),
			dsp(mkDepspec("a 1.0.0"),
				pkg("a", "root/foo"),
			),
		},
		r: mksolution(
			"a 1.0.0",
		),
	},
	"project cycle involving root with backtracking": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0", "a ~1.0.0"),
				pkg("root", "a", "b"),
				pkg("root/foo"),
			),
			dsp(mkDepspec("a 1.0.0"),
				pkg("a", "root/foo"),
			),
			dsp(mkDepspec("a 1.0.1"),
				pkg("a", "root/foo"),
			),
			dsp(mkDepspec("b 1.0.0", "a 1.0.0"),
				pkg("b", "a"),
			),
			dsp(mkDepspec("b 1.0.1", "a 1.0.0"),
				pkg("b", "a"),
			),
			dsp(mkDepspec("b 1.0.2", "a 1.0.0"),
				pkg("b", "a"),
			),
		},
		r: mksolution(
			"a 1.0.0",
			"b 1.0.2",
		),
	},
	"unify project on disjoint package imports + source switching": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0", "b from baz 1.0.0"),
				pkg("root", "a", "b"),
			),
			dsp(mkDepspec("a 1.0.0"),
				pkg("a", "b/foo"),
			),
			dsp(mkDepspec("b 1.0.0"),
				pkg("b"),
				pkg("b/foo"),
			),
			dsp(mkDepspec("baz 1.0.0"),
				pkg("b"),
				pkg("b/foo"),
			),
		},
		r: mksolution(
			"a 1.0.0",
			mklp("b from baz 1.0.0", ".", "foo"),
		),
	},
	"project cycle not involving root": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0", "a ~1.0.0"),
				pkg("root", "a"),
			),
			dsp(mkDepspec("a 1.0.0"),
				pkg("a", "b"),
				pkg("a/foo"),
			),
			dsp(mkDepspec("b 1.0.0"),
				pkg("b", "a/foo"),
			),
		},
		r: mksolution(
			mklp("a 1.0.0", ".", "foo"),
			"b 1.0.0",
		),
	},
	"project cycle not involving root with internal paths": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0", "a ~1.0.0"),
				pkg("root", "a"),
			),
			dsp(mkDepspec("a 1.0.0"),
				pkg("a", "b/baz"),
				pkg("a/foo", "a/quux", "a/quark"),
				pkg("a/quux"),
				pkg("a/quark"),
			),
			dsp(mkDepspec("b 1.0.0"),
				pkg("b", "a/foo"),
				pkg("b/baz", "b"),
			),
		},
		r: mksolution(
			mklp("a 1.0.0", ".", "foo", "quark", "quux"),
			mklp("b 1.0.0", ".", "baz"),
		),
	},
	// Ensure that if a constraint is expressed, but no actual import exists,
	// then the constraint is disregarded - the project named in the constraint
	// is not part of the solution.
	"ignore constraint without import": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0", "a 1.0.0"),
				pkg("root", "root/foo"),
				pkg("root/foo"),
			),
			dsp(mkDepspec("a 1.0.0"),
				pkg("a"),
			),
		},
		r: mksolution(),
	},
	// Transitive deps from one project (a) get incrementally included as other
	// deps incorporate its various packages.
	"multi-stage pkg incorporation": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0"),
				pkg("root", "a", "d"),
			),
			dsp(mkDepspec("a 1.0.0"),
				pkg("a", "b"),
				pkg("a/second", "c"),
			),
			dsp(mkDepspec("b 2.0.0"),
				pkg("b"),
			),
			dsp(mkDepspec("c 1.2.0"),
				pkg("c"),
			),
			dsp(mkDepspec("d 1.0.0"),
				pkg("d", "a/second"),
			),
		},
		r: mksolution(
			mklp("a 1.0.0", ".", "second"),
			"b 2.0.0",
			"c 1.2.0",
			"d 1.0.0",
		),
	},
	// Regression - make sure that the the constraint/import intersector only
	// accepts a project 'match' if exactly equal, or a separating slash is
	// present.
	"radix path separator post-check": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0"),
				pkg("root", "foo", "foobar"),
			),
			dsp(mkDepspec("foo 1.0.0"),
				pkg("foo"),
			),
			dsp(mkDepspec("foobar 1.0.0"),
				pkg("foobar"),
			),
		},
		r: mksolution(
			"foo 1.0.0",
			"foobar 1.0.0",
		),
	},
	// Well-formed failure when there's a dependency on a pkg that doesn't exist
	"fail when imports nonexistent package": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0", "a 1.0.0"),
				pkg("root", "a/foo"),
			),
			dsp(mkDepspec("a 1.0.0"),
				pkg("a"),
			),
		},
		fail: &noVersionError{
			pn: mkPI("a"),
			fails: []failedVersion{
				{
					v: NewVersion("1.0.0"),
					f: &checkeeHasProblemPackagesFailure{
						goal: mkAtom("a 1.0.0"),
						failpkg: map[string]errDeppers{
							"a/foo": {
								err: nil, // nil indicates package is missing
								deppers: []atom{
									mkAtom("root"),
								},
							},
						},
					},
				},
			},
		},
	},
	// Transitive deps from one project (a) get incrementally included as other
	// deps incorporate its various packages, and fail with proper error when we
	// discover one incrementally that isn't present
	"fail multi-stage missing pkg": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0"),
				pkg("root", "a", "d"),
			),
			dsp(mkDepspec("a 1.0.0"),
				pkg("a", "b"),
				pkg("a/second", "c"),
			),
			dsp(mkDepspec("b 2.0.0"),
				pkg("b"),
			),
			dsp(mkDepspec("c 1.2.0"),
				pkg("c"),
			),
			dsp(mkDepspec("d 1.0.0"),
				pkg("d", "a/second"),
				pkg("d", "a/nonexistent"),
			),
		},
		fail: &noVersionError{
			pn: mkPI("d"),
			fails: []failedVersion{
				{
					v: NewVersion("1.0.0"),
					f: &depHasProblemPackagesFailure{
						goal: mkADep("d 1.0.0", "a", Any(), "a/nonexistent"),
						v:    NewVersion("1.0.0"),
						prob: map[string]error{
							"a/nonexistent": nil,
						},
					},
				},
			},
		},
	},
	// Check ignores on the root project
	"ignore in double-subpkg": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0"),
				pkg("root", "root/foo"),
				pkg("root/foo", "root/bar", "b"),
				pkg("root/bar", "a"),
			),
			dsp(mkDepspec("a 1.0.0"),
				pkg("a"),
			),
			dsp(mkDepspec("b 1.0.0"),
				pkg("b"),
			),
		},
		ignore: []string{"root/bar"},
		r: mksolution(
			"b 1.0.0",
		),
	},
	// Ignores on a dep pkg
	"ignore through dep pkg": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0"),
				pkg("root", "root/foo"),
				pkg("root/foo", "a"),
			),
			dsp(mkDepspec("a 1.0.0"),
				pkg("a", "a/bar"),
				pkg("a/bar", "b"),
			),
			dsp(mkDepspec("b 1.0.0"),
				pkg("b"),
			),
		},
		ignore: []string{"a/bar"},
		r: mksolution(
			"a 1.0.0",
		),
	},
	// Preferred version, as derived from a dep's lock, is attempted first
	"respect prefv, simple case": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0"),
				pkg("root", "a")),
			dsp(mkDepspec("a 1.0.0"),
				pkg("a", "b")),
			dsp(mkDepspec("b 1.0.0 foorev"),
				pkg("b")),
			dsp(mkDepspec("b 2.0.0 barrev"),
				pkg("b")),
		},
		lm: map[string]fixLock{
			"a 1.0.0": mklock(
				"b 1.0.0 foorev",
			),
		},
		r: mksolution(
			"a 1.0.0",
			"b 1.0.0 foorev",
		),
	},
	// Preferred version, as derived from a dep's lock, is attempted first, even
	// if the root also has a direct dep on it (root doesn't need to use
	// preferreds, because it has direct control AND because the root lock
	// already supersedes dep lock "preferences")
	"respect dep prefv with root import": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0"),
				pkg("root", "a", "b")),
			dsp(mkDepspec("a 1.0.0"),
				pkg("a", "b")),
			//dsp(newDepspec("a 1.0.1"),
			//pkg("a", "b")),
			//dsp(newDepspec("a 1.1.0"),
			//pkg("a", "b")),
			dsp(mkDepspec("b 1.0.0 foorev"),
				pkg("b")),
			dsp(mkDepspec("b 2.0.0 barrev"),
				pkg("b")),
		},
		lm: map[string]fixLock{
			"a 1.0.0": mklock(
				"b 1.0.0 foorev",
			),
		},
		r: mksolution(
			"a 1.0.0",
			"b 1.0.0 foorev",
		),
	},
	// Preferred versions can only work if the thing offering it has been
	// selected, or at least marked in the unselected queue
	"prefv only works if depper is selected": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0"),
				pkg("root", "a", "b")),
			// Three atoms for a, which will mean it gets visited after b
			dsp(mkDepspec("a 1.0.0"),
				pkg("a", "b")),
			dsp(mkDepspec("a 1.0.1"),
				pkg("a", "b")),
			dsp(mkDepspec("a 1.1.0"),
				pkg("a", "b")),
			dsp(mkDepspec("b 1.0.0 foorev"),
				pkg("b")),
			dsp(mkDepspec("b 2.0.0 barrev"),
				pkg("b")),
		},
		lm: map[string]fixLock{
			"a 1.0.0": mklock(
				"b 1.0.0 foorev",
			),
		},
		r: mksolution(
			"a 1.1.0",
			"b 2.0.0 barrev",
		),
	},
	"override unconstrained root import": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0"),
				pkg("root", "a")),
			dsp(mkDepspec("a 1.0.0"),
				pkg("a")),
			dsp(mkDepspec("a 2.0.0"),
				pkg("a")),
		},
		ovr: ProjectConstraints{
			ProjectRoot("a"): ProjectProperties{
				Constraint: NewVersion("1.0.0"),
			},
		},
		r: mksolution(
			"a 1.0.0",
		),
	},
	"simple case-only differences": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0"),
				pkg("root", "foo", "bar")),
			dsp(mkDepspec("foo 1.0.0"),
				pkg("foo", "Bar")),
			dsp(mkDepspec("bar 1.0.0"),
				pkg("bar")),
		},
		fail: &noVersionError{
			pn: mkPI("foo"),
			fails: []failedVersion{
				{
					v: NewVersion("1.0.0"),
					f: &caseMismatchFailure{
						goal:    mkDep("foo 1.0.0", "Bar 1.0.0", "Bar"),
						current: ProjectRoot("bar"),
						failsib: []dependency{mkDep("root", "bar 1.0.0", "bar")},
					},
				},
			},
		},
	},
	"case variations acceptable with agreement": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0"),
				pkg("root", "foo")),
			dsp(mkDepspec("foo 1.0.0"),
				pkg("foo", "Bar", "baz")),
			dsp(mkDepspec("baz 1.0.0"),
				pkg("baz", "Bar")),
			dsp(mkDepspec("bar 1.0.0"),
				pkg("bar")),
		},
		r: mksolution(
			"foo 1.0.0",
			"Bar 1.0.0",
			"baz 1.0.0",
		),
	},
	"case variations within root": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0"),
				pkg("root", "foo", "bar", "Bar")),
			dsp(mkDepspec("foo 1.0.0"),
				pkg("foo")),
			dsp(mkDepspec("bar 1.0.0"),
				pkg("bar")),
		},
		fail: &noVersionError{
			pn: mkPI("foo"),
			fails: []failedVersion{
				{
					v: NewVersion("1.0.0"),
					f: &caseMismatchFailure{
						goal:    mkDep("foo 1.0.0", "Bar 1.0.0", "Bar"),
						current: ProjectRoot("bar"),
						failsib: []dependency{mkDep("root", "foo 1.0.0", "foo")},
					},
				},
			},
		},
		broken: "need to implement checking for import case variations *within* the root",
	},
	"case variations within single dep": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0"),
				pkg("root", "foo")),
			dsp(mkDepspec("foo 1.0.0"),
				pkg("foo", "bar", "Bar")),
			dsp(mkDepspec("bar 1.0.0"),
				pkg("bar")),
		},
		fail: &noVersionError{
			pn: mkPI("foo"),
			fails: []failedVersion{
				{
					v: NewVersion("1.0.0"),
					f: &caseMismatchFailure{
						goal:    mkDep("foo 1.0.0", "Bar 1.0.0", "Bar"),
						current: ProjectRoot("bar"),
						failsib: []dependency{mkDep("root", "foo 1.0.0", "foo")},
					},
				},
			},
		},
		broken: "need to implement checking for import case variations *within* a single project",
	},
	"case variations across multiple deps": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0"),
				pkg("root", "foo", "bar")),
			dsp(mkDepspec("foo 1.0.0"),
				pkg("foo", "bar", "baz")),
			dsp(mkDepspec("baz 1.0.0"),
				pkg("baz", "Bar")),
			dsp(mkDepspec("bar 1.0.0"),
				pkg("bar")),
		},
		fail: &noVersionError{
			pn: mkPI("baz"),
			fails: []failedVersion{
				{
					v: NewVersion("1.0.0"),
					f: &caseMismatchFailure{
						goal:    mkDep("baz 1.0.0", "Bar 1.0.0", "Bar"),
						current: ProjectRoot("bar"),
						failsib: []dependency{
							mkDep("root", "bar 1.0.0", "bar"),
							mkDep("foo 1.0.0", "bar 1.0.0", "bar"),
						},
					},
				},
			},
		},
	},
	// This isn't actually as crazy as it might seem, as the root is defined by
	// the addresser, not the addressee. It would occur (to provide a
	// real-as-of-this-writing example) if something imports
	// github.com/Sirupsen/logrus, as the contained subpackage at
	// github.com/Sirupsen/logrus/hooks/syslog imports
	// github.com/sirupsen/logrus. The only reason that doesn't blow up all the
	// time is that most people only import the root package, not the syslog
	// subpackage.
	"canonical case is established by mutual self-imports": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0"),
				pkg("root", "foo")),
			dsp(mkDepspec("foo 1.0.0"),
				pkg("foo", "Bar")),
			dsp(mkDepspec("bar 1.0.0"),
				pkg("bar", "bar/subpkg"),
				pkg("bar/subpkg")),
		},
		fail: &noVersionError{
			pn: mkPI("Bar"),
			fails: []failedVersion{
				{
					v: NewVersion("1.0.0"),
					f: &wrongCaseFailure{
						correct: ProjectRoot("bar"),
						goal:    mkDep("Bar 1.0.0", "bar 1.0.0", "bar"),
						badcase: []dependency{mkDep("foo 1.0.0", "Bar 1.0.0", "Bar/subpkg")},
					},
				},
			},
		},
	},
	"canonical case only applies if relevant imports are activated": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0"),
				pkg("root", "foo")),
			dsp(mkDepspec("foo 1.0.0"),
				pkg("foo", "Bar/subpkg")),
			dsp(mkDepspec("bar 1.0.0"),
				pkg("bar", "bar/subpkg"),
				pkg("bar/subpkg")),
		},
		r: mksolution(
			"foo 1.0.0",
			mklp("Bar 1.0.0", "subpkg"),
		),
	},
	"simple case-only variations plus source variance": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0"),
				pkg("root", "foo", "bar")),
			dsp(mkDepspec("foo 1.0.0", "Bar from quux 1.0.0"),
				pkg("foo", "Bar")),
			dsp(mkDepspec("bar 1.0.0"),
				pkg("bar")),
			dsp(mkDepspec("quux 1.0.0"),
				pkg("bar")),
		},
		fail: &noVersionError{
			pn: mkPI("foo"),
			fails: []failedVersion{
				{
					v: NewVersion("1.0.0"),
					f: &caseMismatchFailure{
						goal:    mkDep("foo 1.0.0", "Bar from quux 1.0.0", "Bar"),
						current: ProjectRoot("bar"),
						failsib: []dependency{mkDep("root", "bar 1.0.0", "bar")},
					},
				},
			},
		},
	},
	"case-only variations plus source variance with internal canonicality": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0", "Bar from quux 1.0.0"),
				pkg("root", "foo", "Bar")),
			dsp(mkDepspec("foo 1.0.0", "Bar from quux 1.0.0"),
				pkg("foo", "Bar")),
			dsp(mkDepspec("bar 1.0.0"),
				pkg("bar", "bar/subpkg"),
				pkg("bar/subpkg")),
			dsp(mkDepspec("quux 1.0.0"),
				pkg("bar", "bar/subpkg"),
				pkg("bar/subpkg")),
		},
		fail: &noVersionError{
			pn: mkPI("Bar"),
			fails: []failedVersion{
				{
					v: NewVersion("1.0.0"),
					f: &wrongCaseFailure{
						correct: ProjectRoot("bar"),
						goal:    mkDep("Bar from quux 1.0.0", "bar 1.0.0", "bar"),
						badcase: []dependency{mkDep("root", "Bar 1.0.0", "Bar/subpkg")},
					},
				},
			},
		},
	},
	"alternate net address": {
		ds: []depspec{
			dsp(mkDepspec("root 1.0.0", "foo from bar 2.0.0"),
				pkg("root", "foo")),
			dsp(mkDepspec("foo 1.0.0"),
				pkg("foo")),
			dsp(mkDepspec("foo 2.0.0"),
				pkg("foo")),
			dsp(mkDepspec("bar 1.0.0"),
				pkg("foo")),
			dsp(mkDepspec("bar 2.0.0"),
				pkg("foo")),
		},
		r: mksolution(
			"foo from bar 2.0.0",
		),
	},
	"alternate net address, version only in alt": {
		ds: []depspec{
			dsp(mkDepspec("root 1.0.0", "foo from bar 2.0.0"),
				pkg("root", "foo")),
			dsp(mkDepspec("foo 1.0.0"),
				pkg("foo")),
			dsp(mkDepspec("bar 1.0.0"),
				pkg("foo")),
			dsp(mkDepspec("bar 2.0.0"),
				pkg("foo")),
		},
		r: mksolution(
			"foo from bar 2.0.0",
		),
	},
	"alternate net address in dep": {
		ds: []depspec{
			dsp(mkDepspec("root 1.0.0", "foo 1.0.0"),
				pkg("root", "foo")),
			dsp(mkDepspec("foo 1.0.0", "bar from baz 2.0.0"),
				pkg("foo", "bar")),
			dsp(mkDepspec("bar 1.0.0"),
				pkg("bar")),
			dsp(mkDepspec("baz 1.0.0"),
				pkg("bar")),
			dsp(mkDepspec("baz 2.0.0"),
				pkg("bar")),
		},
		r: mksolution(
			"foo 1.0.0",
			"bar from baz 2.0.0",
		),
	},
	// Because NOT specifying an alternate net address for a given import path
	// is taken as an "eh, whatever", if we see an empty net addr after
	// something else has already set an alternate one, then the second should
	// just "go along" with whatever's already been specified.
	"alternate net address with second depper": {
		ds: []depspec{
			dsp(mkDepspec("root 1.0.0", "foo from bar 2.0.0"),
				pkg("root", "foo", "baz")),
			dsp(mkDepspec("foo 1.0.0"),
				pkg("foo")),
			dsp(mkDepspec("foo 2.0.0"),
				pkg("foo")),
			dsp(mkDepspec("bar 1.0.0"),
				pkg("foo")),
			dsp(mkDepspec("bar 2.0.0"),
				pkg("foo")),
			dsp(mkDepspec("baz 1.0.0"),
				pkg("baz", "foo")),
		},
		r: mksolution(
			"foo from bar 2.0.0",
			"baz 1.0.0",
		),
	},
	// Same as the previous, except the alternate declaration originates in a
	// dep, not the root.
	"alternate net addr from dep, with second default depper": {
		ds: []depspec{
			dsp(mkDepspec("root 1.0.0", "foo 1.0.0"),
				pkg("root", "foo", "bar")),
			dsp(mkDepspec("foo 1.0.0", "bar 2.0.0"),
				pkg("foo", "baz")),
			dsp(mkDepspec("foo 2.0.0", "bar 2.0.0"),
				pkg("foo", "baz")),
			dsp(mkDepspec("bar 2.0.0", "baz from quux 1.0.0"),
				pkg("bar", "baz")),
			dsp(mkDepspec("baz 1.0.0"),
				pkg("baz")),
			dsp(mkDepspec("baz 2.0.0"),
				pkg("baz")),
			dsp(mkDepspec("quux 1.0.0"),
				pkg("baz")),
		},
		r: mksolution(
			"foo 1.0.0",
			"bar 2.0.0",
			"baz from quux 1.0.0",
		),
	},
	// When a given project is initially brought in using the default (i.e.,
	// empty) ProjectIdentifier.Source, and a later, presumably
	// as-yet-undiscovered dependency specifies an alternate net addr for it, we
	// have to fail - even though, if the deps were visited in the opposite
	// order (deeper dep w/the alternate location first, default location
	// second), it would be fine.
	//
	// TODO A better solution here would involve restarting the solver w/a
	// marker to use that alternate, or (ugh) introducing a new failure
	// path/marker type that changes how backtracking works. (In fact, these
	// approaches are probably demonstrably equivalent.)
	"fails with net mismatch when deeper dep specs it": {
		ds: []depspec{
			dsp(mkDepspec("root 1.0.0", "foo 1.0.0"),
				pkg("root", "foo", "baz")),
			dsp(mkDepspec("foo 1.0.0", "bar 2.0.0"),
				pkg("foo", "bar")),
			dsp(mkDepspec("bar 2.0.0", "baz from quux 1.0.0"),
				pkg("bar", "baz")),
			dsp(mkDepspec("baz 1.0.0"),
				pkg("baz")),
			dsp(mkDepspec("quux 1.0.0"),
				pkg("baz")),
		},
		fail: &noVersionError{
			pn: mkPI("bar"),
			fails: []failedVersion{
				{
					v: NewVersion("2.0.0"),
					f: &sourceMismatchFailure{
						shared:   ProjectRoot("baz"),
						current:  "baz",
						mismatch: "quux",
						prob:     mkAtom("bar 2.0.0"),
						sel:      []dependency{mkDep("foo 1.0.0", "bar 2.0.0", "bar")},
					},
				},
			},
		},
	},
	"with mismatched net addrs": {
		ds: []depspec{
			dsp(mkDepspec("root 1.0.0", "foo 1.0.0", "bar 1.0.0"),
				pkg("root", "foo", "bar")),
			dsp(mkDepspec("foo 1.0.0", "bar from baz 1.0.0"),
				pkg("foo", "bar")),
			dsp(mkDepspec("bar 1.0.0"),
				pkg("bar")),
			dsp(mkDepspec("baz 1.0.0"),
				pkg("bar")),
		},
		fail: &noVersionError{
			pn: mkPI("foo"),
			fails: []failedVersion{
				{
					v: NewVersion("1.0.0"),
					f: &sourceMismatchFailure{
						shared:   ProjectRoot("bar"),
						current:  "bar",
						mismatch: "baz",
						prob:     mkAtom("foo 1.0.0"),
						sel:      []dependency{mkDep("root", "foo 1.0.0", "foo")},
					},
				},
			},
		},
	},
	"overridden mismatched net addrs, alt in dep": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0"),
				pkg("root", "foo")),
			dsp(mkDepspec("foo 1.0.0", "bar from baz 1.0.0"),
				pkg("foo", "bar")),
			dsp(mkDepspec("bar 1.0.0"),
				pkg("bar")),
			dsp(mkDepspec("baz 1.0.0"),
				pkg("bar")),
		},
		ovr: ProjectConstraints{
			ProjectRoot("bar"): ProjectProperties{
				Source: "baz",
			},
		},
		r: mksolution(
			"foo 1.0.0",
			"bar from baz 1.0.0",
		),
	},
	"overridden mismatched net addrs, alt in root": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0", "bar from baz 1.0.0"),
				pkg("root", "foo")),
			dsp(mkDepspec("foo 1.0.0"),
				pkg("foo", "bar")),
			dsp(mkDepspec("bar 1.0.0"),
				pkg("bar")),
			dsp(mkDepspec("baz 1.0.0"),
				pkg("bar")),
		},
		ovr: ProjectConstraints{
			ProjectRoot("bar"): ProjectProperties{
				Source: "baz",
			},
		},
		r: mksolution(
			"foo 1.0.0",
			"bar from baz 1.0.0",
		),
	},
	"require package": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0", "bar 1.0.0"),
				pkg("root", "foo")),
			dsp(mkDepspec("foo 1.0.0"),
				pkg("foo", "bar")),
			dsp(mkDepspec("bar 1.0.0"),
				pkg("bar")),
			dsp(mkDepspec("baz 1.0.0"),
				pkg("baz")),
		},
		require: []string{"baz"},
		r: mksolution(
			"foo 1.0.0",
			"bar 1.0.0",
			"baz 1.0.0",
		),
	},
	"require activates constraints": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0", "foo 1.0.0", "bar 1.0.0"),
				pkg("root", "foo")),
			dsp(mkDepspec("foo 1.0.0"),
				pkg("foo", "bar")),
			dsp(mkDepspec("bar 1.0.0"),
				pkg("bar")),
			dsp(mkDepspec("bar 1.1.0"),
				pkg("bar")),
		},
		require: []string{"bar"},
		r: mksolution(
			"foo 1.0.0",
			"bar 1.0.0",
		),
	},
	"require subpackage": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0", "bar 1.0.0"),
				pkg("root", "foo")),
			dsp(mkDepspec("foo 1.0.0"),
				pkg("foo", "bar")),
			dsp(mkDepspec("bar 1.0.0"),
				pkg("bar")),
			dsp(mkDepspec("baz 1.0.0"),
				pkg("baz", "baz/qux"),
				pkg("baz/qux")),
		},
		require: []string{"baz/qux"},
		r: mksolution(
			"foo 1.0.0",
			"bar 1.0.0",
			mklp("baz 1.0.0", "qux"),
		),
	},
	"require impossible subpackage": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0", "baz 1.0.0"),
				pkg("root", "foo")),
			dsp(mkDepspec("foo 1.0.0"),
				pkg("foo")),
			dsp(mkDepspec("baz 1.0.0"),
				pkg("baz")),
			dsp(mkDepspec("baz 2.0.0"),
				pkg("baz", "baz/qux"),
				pkg("baz/qux")),
		},
		require: []string{"baz/qux"},
		fail: &noVersionError{
			pn: mkPI("baz"),
			fails: []failedVersion{
				{
					v: NewVersion("2.0.0"),
					f: &versionNotAllowedFailure{
						goal:       mkAtom("baz 2.0.0"),
						failparent: []dependency{mkDep("root", "baz 1.0.0", "baz/qux")},
						c:          NewVersion("1.0.0"),
					},
				},
				{
					v: NewVersion("1.0.0"),
					f: &checkeeHasProblemPackagesFailure{
						goal: mkAtom("baz 1.0.0"),
						failpkg: map[string]errDeppers{
							"baz/qux": {
								err: nil, // nil indicates package is missing
								deppers: []atom{
									mkAtom("root"),
								},
							},
						},
					},
				},
			},
		},
	},
	"require subpkg conflicts with other dep constraint": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0"),
				pkg("root", "foo")),
			dsp(mkDepspec("foo 1.0.0", "baz 1.0.0"),
				pkg("foo", "baz")),
			dsp(mkDepspec("baz 1.0.0"),
				pkg("baz")),
			dsp(mkDepspec("baz 2.0.0"),
				pkg("baz", "baz/qux"),
				pkg("baz/qux")),
		},
		require: []string{"baz/qux"},
		fail: &noVersionError{
			pn: mkPI("baz"),
			fails: []failedVersion{
				{
					v: NewVersion("2.0.0"),
					f: &versionNotAllowedFailure{
						goal:       mkAtom("baz 2.0.0"),
						failparent: []dependency{mkDep("foo 1.0.0", "baz 1.0.0", "baz")},
						c:          NewVersion("1.0.0"),
					},
				},
				{
					v: NewVersion("1.0.0"),
					f: &checkeeHasProblemPackagesFailure{
						goal: mkAtom("baz 1.0.0"),
						failpkg: map[string]errDeppers{
							"baz/qux": {
								err: nil, // nil indicates package is missing
								deppers: []atom{
									mkAtom("root"),
								},
							},
						},
					},
				},
			},
		},
	},
	"require independent subpkg conflicts with other dep constraint": {
		ds: []depspec{
			dsp(mkDepspec("root 0.0.0"),
				pkg("root", "foo")),
			dsp(mkDepspec("foo 1.0.0", "baz 1.0.0"),
				pkg("foo", "baz")),
			dsp(mkDepspec("baz 1.0.0"),
				pkg("baz")),
			dsp(mkDepspec("baz 2.0.0"),
				pkg("baz"),
				pkg("baz/qux")),
		},
		require: []string{"baz/qux"},
		fail: &noVersionError{
			pn: mkPI("baz"),
			fails: []failedVersion{
				{
					v: NewVersion("2.0.0"),
					f: &versionNotAllowedFailure{
						goal:       mkAtom("baz 2.0.0"),
						failparent: []dependency{mkDep("foo 1.0.0", "baz 1.0.0", "baz")},
						c:          NewVersion("1.0.0"),
					},
				},
				{
					v: NewVersion("1.0.0"),
					f: &checkeeHasProblemPackagesFailure{
						goal: mkAtom("baz 1.0.0"),
						failpkg: map[string]errDeppers{
							"baz/qux": {
								err: nil, // nil indicates package is missing
								deppers: []atom{
									mkAtom("root"),
								},
							},
						},
					},
				},
			},
		},
	},
}

// tpkg is a representation of a single package. It has its own import path, as
// well as a list of paths it itself "imports".
type tpkg struct {
	// Full import path of this package
	path string
	// Slice of full paths to its virtual imports
	imports []string
}

type bimodalFixture struct {
	// name of this fixture datum
	n string
	// bimodal project; first is always treated as root project
	ds []depspec
	// results; map of name/version pairs
	r map[ProjectIdentifier]LockedProject
	// max attempts the solver should need to find solution. 0 means no limit
	maxAttempts int
	// Use downgrade instead of default upgrade sorter
	downgrade bool
	// lock file simulator, if one's to be used at all
	l fixLock
	// map of locks for deps, if any. keys should be of the form:
	// "<project> <version>"
	lm map[string]fixLock
	// solve failure expected, if any
	fail error
	// overrides, if any
	ovr ProjectConstraints
	// request up/downgrade to all projects
	changeall bool
	// pkgs to ignore
	ignore []string
	// pkgs to require
	require []string
	// if the fixture is currently broken/expected to fail, this has a message
	// recording why
	broken string
}

func (f bimodalFixture) name() string {
	return f.n
}

func (f bimodalFixture) specs() []depspec {
	return f.ds
}

func (f bimodalFixture) maxTries() int {
	return f.maxAttempts
}

func (f bimodalFixture) solution() map[ProjectIdentifier]LockedProject {
	return f.r
}

func (f bimodalFixture) rootmanifest() RootManifest {
	m := simpleRootManifest{
		c:   pcSliceToMap(f.ds[0].deps),
		ovr: f.ovr,
		ig:  pkgtree.NewIgnoredRuleset(f.ignore),
		req: make(map[string]bool),
	}
	for _, req := range f.require {
		m.req[req] = true
	}

	return m
}

func (f bimodalFixture) rootTree() pkgtree.PackageTree {
	pt := pkgtree.PackageTree{
		ImportRoot: string(f.ds[0].n),
		Packages:   map[string]pkgtree.PackageOrErr{},
	}

	for _, pkg := range f.ds[0].pkgs {
		elems := strings.Split(pkg.path, "/")
		pt.Packages[pkg.path] = pkgtree.PackageOrErr{
			P: pkgtree.Package{
				ImportPath: pkg.path,
				Name:       elems[len(elems)-1],
				// TODO(sdboyer) ugh, tpkg type has no space for supporting test
				// imports...
				Imports: pkg.imports,
			},
		}
	}

	return pt
}

func (f bimodalFixture) failure() error {
	return f.fail
}

// bmSourceManager is an SM specifically for the bimodal fixtures. It composes
// the general depspec SM, and differs from it in how it answers static analysis
// calls, and its support for package ignores and dep lock data.
type bmSourceManager struct {
	depspecSourceManager
	lm map[string]fixLock
}

var _ SourceManager = &bmSourceManager{}

func newbmSM(bmf bimodalFixture) *bmSourceManager {
	sm := &bmSourceManager{
		depspecSourceManager: *newdepspecSM(bmf.ds, bmf.ignore),
	}
	sm.rm = computeBimodalExternalMap(bmf.ds)
	sm.lm = bmf.lm

	return sm
}

func (sm *bmSourceManager) ListPackages(id ProjectIdentifier, v Version) (pkgtree.PackageTree, error) {
	// Deal with address-based root-switching with both case folding and
	// alternate sources.
	var src, fsrc, root, froot string
	src, fsrc = id.normalizedSource(), toFold(id.normalizedSource())
	if id.Source != "" {
		root = string(id.ProjectRoot)
		froot = toFold(root)
	} else {
		root, froot = src, fsrc
	}

	for k, ds := range sm.specs {
		// Cheat for root, otherwise we blow up b/c version is empty
		if fsrc == string(ds.n) && (k == 0 || ds.v.Matches(v)) {
			var replace bool
			if root != string(ds.n) {
				// We're in a case-varying lookup; ensure we replace the actual
				// leading ProjectRoot portion of import paths with the literal
				// string from the input.
				replace = true
			}

			ptree := pkgtree.PackageTree{
				ImportRoot: src,
				Packages:   make(map[string]pkgtree.PackageOrErr),
			}
			for _, pkg := range ds.pkgs {
				if replace {
					pkg.path = strings.Replace(pkg.path, froot, root, 1)
				}
				ptree.Packages[pkg.path] = pkgtree.PackageOrErr{
					P: pkgtree.Package{
						ImportPath: pkg.path,
						Name:       filepath.Base(pkg.path),
						Imports:    pkg.imports,
					},
				}
			}

			return ptree, nil
		}
	}

	return pkgtree.PackageTree{}, fmt.Errorf("project %s at version %s could not be found", id, v)
}

func (sm *bmSourceManager) GetManifestAndLock(id ProjectIdentifier, v Version, an ProjectAnalyzer) (Manifest, Lock, error) {
	src := toFold(id.normalizedSource())
	for _, ds := range sm.specs {
		if src == string(ds.n) && v.Matches(ds.v) {
			if l, exists := sm.lm[src+" "+v.String()]; exists {
				return ds, l, nil
			}
			return ds, dummyLock{}, nil
		}
	}

	// TODO(sdboyer) proper solver-type errors
	return nil, nil, fmt.Errorf("project %s at version %s could not be found", id, v)
}

// computeBimodalExternalMap takes a set of depspecs and computes an
// internally-versioned ReachMap that is useful for quickly answering
// ReachMap.Flatten()-type calls.
//
// Note that it does not do things like stripping out stdlib packages - these
// maps are intended for use in SM fixtures, and that's a higher-level
// responsibility within the system.
func computeBimodalExternalMap(specs []depspec) map[pident]map[string][]string {
	// map of project name+version -> map of subpkg name -> external pkg list
	rm := make(map[pident]map[string][]string)

	for _, ds := range specs {
		ptree := pkgtree.PackageTree{
			ImportRoot: string(ds.n),
			Packages:   make(map[string]pkgtree.PackageOrErr),
		}
		for _, pkg := range ds.pkgs {
			ptree.Packages[pkg.path] = pkgtree.PackageOrErr{
				P: pkgtree.Package{
					ImportPath: pkg.path,
					Name:       filepath.Base(pkg.path),
					Imports:    pkg.imports,
				},
			}
		}
		reachmap, em := ptree.ToReachMap(false, true, true, nil)
		if len(em) > 0 {
			panic(fmt.Sprintf("pkgs with errors in reachmap processing: %s", em))
		}

		drm := make(map[string][]string)
		for ip, ie := range reachmap {
			drm[ip] = ie.External
		}
		rm[pident{n: ds.n, v: ds.v}] = drm
	}

	return rm
}
